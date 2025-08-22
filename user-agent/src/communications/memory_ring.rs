// communications/memory_ring.rs
//! High‑performance reader for the kernel ring buffer (user‑mode side).
//!
//! The kernel exposes a SECTION that backs a single‑producer/single‑consumer ring. Instead of
//! opening it by name (fragile across sessions and integrity levels), we ask the driver to broker
//! a handle via an IOCTL and then map it locally. This type provides a safe, idiomatic iterator
//! over length‑prefixed frames, using acquire/release semantics compatible with the kernel writer.
//!
//! Frame format: `[u32 len_le][payload]`, naturally wrapping at the end of the data region.
//!
//! Concurrency model: single producer in kernel, single consumer in user‑mode. No locks required.
//! Tail is mirrored back to the shared header so the producer can make forward progress.
//!
//! TODO: consider optional backoff/yield strategy when no frames are ready, to reduce CPU usage.

use crate::communications::ioctl::request_section_handle;
use log::{debug, info, warn};
use std::{
    io,
    mem::{size_of},
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
    vec::Vec,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Memory::{
        MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
    },
};

const LEN_PREFIX: usize = size_of::<u32>();

/// On‑shared‑memory header laid out by the kernel driver (same layout on both sides).
#[repr(C)]
struct Header {
    head:    AtomicU32, // producer cursor (bytes into data region)
    tail:    AtomicU32, // consumer cursor (mirrored by us)
    dropped: AtomicU32, // number of producer drops (no space)
    size:    u32,       // data region size, in bytes (excludes header)
}

/// RAII mapping wrapper: keeps both the section handle and the mapped view alive.
struct Mapping {
    handle: HANDLE,
    view:   NonNull<u8>, // base address of the mapping (points to Header)
}

unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Map the section returned by the driver for read/write consumption.
    ///
    /// Mapping with both read and write allows the consumer to advance `tail` in the shared header.
    fn open_via_ioctl() -> io::Result<Self> {
        let handle = request_section_handle()?;

        // Map the entire section. Zero length requests the full size.
        let view_addr: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) };

        if view_addr.Value.is_null() {
            let err = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(err);
        }

        // SAFETY: non‑NULL checked above.
        let view = unsafe { NonNull::new_unchecked(view_addr.Value as *mut u8) };
        info!("Mapped ring view at {:p}", view.as_ptr());
        Ok(Self { handle, view })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            let addr = MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.view.as_ptr() as _,
            };
            UnmapViewOfFile(addr);
            CloseHandle(self.handle);
        }
        debug!("Unmapped ring view and closed section handle");
    }
}

/// Ring buffer reader for the shared memory section.
///
/// The consumer maintains a private `tail` cursor and mirrors it back to the shared header after
/// each successful read. Methods that expose state (`head`, `tail`, `capacity`, `dropped_count`)
/// use atomic loads consistent with the SPSC contract.
pub struct MemoryRing {
    hdr:  &'static Header,
    buf:  *const u8, // start of data region (after Header)
    size: u32,       // cached from header at open
    tail: u32,       // consumer cursor (bytes into data region)
    _map: Mapping,   // owns the mapping lifetime
}

unsafe impl Send for MemoryRing {}
unsafe impl Sync for MemoryRing {}

impl MemoryRing {
    /// Open and map the ring by requesting a brokered section handle from the driver.
    ///
    /// The `name` parameter is intentionally ignored; the brokered handle avoids Global\ name and
    /// integrity level issues. The initial `tail` snapshot is taken from the shared header.
    ///
    /// # Errors
    /// Returns an `io::Error` if the IOCTL or mapping fails.
    pub fn open(_ignored_name: &str) -> io::Result<Self> {
        let map = Mapping::open_via_ioctl()?;

        // SAFETY: mapping is valid and large enough for a Header at the base.
        let hdr: &Header = unsafe { &*(map.view.as_ptr() as *const Header) };
        let size = hdr.size;
        let buf = unsafe { map.view.as_ptr().add(size_of::<Header>()) };
        let tail = hdr.tail.load(Ordering::Acquire);

        // Minimal sanity: zero size means the kernel side hasn't initialized the header.
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "ring header reports zero data size",
            ));
        }

        info!("Section open: data_size={size} initial_tail={tail}");
        Ok(Self { hdr, buf, size, tail, _map: map })
    }

    /// Return the next complete frame, or `None` if the producer is caught up or still writing.
    ///
    /// This performs wrap‑safe reads of the 4‑byte length prefix and the payload. If a corrupted
    /// length is observed, the reader will resynchronize by setting `tail = head`.
    #[inline]
    pub fn read_next(&mut self) -> Option<Vec<u8>> {
        let head = self.hdr.head.load(Ordering::Acquire);
        if self.tail == head {
            return None;
        }

        // Read the length prefix with wrap‑around.
        let len = {
            let mut tmp = [0u8; LEN_PREFIX];
            self.copy_circular(self.tail, &mut tmp);
            u32::from_le_bytes(tmp)
        };

        // Quick sanity: reject obviously invalid lengths.
        if len == 0 || len > self.size.saturating_sub(LEN_PREFIX as u32) {
            warn!("Corrupt frame: len={len}, forcing tail=head ({head})");
            self.tail = head;
            self.hdr.tail.store(self.tail, Ordering::Release);
            return None;
        }

        // Ensure the full frame is available up to `head`.
        let available = if self.tail <= head {
            head - self.tail
        } else {
            self.size - self.tail + head
        };
        if available < len + LEN_PREFIX as u32 {
            // Producer hasn't published the full frame yet; try again later.
            return None;
        }

        // Copy out the payload with wrap‑around if needed.
        let mut out = vec![0u8; len as usize];
        self.copy_circular(self.tail + LEN_PREFIX as u32, &mut out);

        // Advance consumer cursor and mirror to the shared header.
        let new_tail = (self.tail + LEN_PREFIX as u32 + len) % self.size;
        self.tail = new_tail;
        self.hdr.tail.store(self.tail, Ordering::Release);

        debug!("read_next: len={} head={} new_tail={}", len, head, new_tail);
        Some(out)
    }

    /// Returns true if the reader is caught up with the producer.
    #[inline]
    pub fn is_empty(&self) -> bool {
        let head = self.hdr.head.load(Ordering::Acquire);
        self.tail == head
    }

    /// Skip all currently buffered frames by setting `tail = head`. This is useful to quickly
    /// drain bursty noise or recover from unexpected backlog.
    pub fn skip_all(&mut self) {
        let head = self.hdr.head.load(Ordering::Acquire);
        self.tail = head;
        self.hdr.tail.store(head, Ordering::Release);
    }

    /// Current producer cursor as observed by the consumer.
    #[inline]
    pub fn head(&self) -> u32 {
        self.hdr.head.load(Ordering::Acquire)
    }

    /// Current consumer cursor.
    #[inline]
    pub fn tail(&self) -> u32 {
        self.tail
    }

    /// Data region capacity in bytes (excludes header).
    #[inline]
    pub fn capacity(&self) -> u32 {
        self.size
    }

    /// Number of frames the producer dropped due to lack of space.
    #[inline]
    pub fn dropped_count(&self) -> u32 {
        self.hdr.dropped.load(Ordering::Relaxed)
    }

    /// Copy `dst.len()` bytes starting at `off` modulo `size` into `dst`, handling wrap‑around.
    #[inline]
    fn copy_circular(&self, mut off: u32, dst: &mut [u8]) {
        let size = self.size as usize;
        let base = self.buf as usize;
        let mut done = 0usize;
        let mut rem = dst.len();

        while rem != 0 {
            let to_end = size - off as usize;
            let chunk = rem.min(to_end);
            // SAFETY: the mapping is valid; `off` is always modulo `size`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (base + off as usize) as *const u8,
                    dst.as_mut_ptr().add(done),
                    chunk,
                );
            }
            done += chunk;
            rem -= chunk;
            off = (off + chunk as u32) % self.size;
        }
    }
}

/// Support `for frame in ring` ergonomics with a pull‑based iterator.
impl Iterator for MemoryRing {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        self.read_next()
    }
}
