//! memory_ring.rs
//!
//! Kernel‑side single‑producer/single‑consumer ring buffer backed by a named SECTION.
//! Frames are length‑prefixed as `[u32 len_le][payload]` and are written with natural
//! wrap‑around. The producer drops a frame if there is not enough free space.
//!
//! Why a SECTION:
//! - The ring is mapped once in system space for the kernel producer.
//! - The same SECTION is opened and mapped by user mode to consume events without copies.
//!
//! Concurrency model:
//! - Single producer in kernel, single consumer in user mode.
//! - `head` is written by the producer; `tail` by the consumer.
//! - `head` is published with `Release` and `tail` is read with `Acquire` so that payload
//!   stores become visible to the consumer that advances `tail` after reading.
//!
//! Logging policy:
//! - Creation/mapping/unmapping logs are retained (happen a handful of times per lifecycle).
//! - Per‑push logs are gated behind the `ring-trace` Cargo feature to avoid flooding.

use crate::security::{SecurityDescriptor, SECTION_RW_MASK};
use crate::utils::initialize_object_attributes;

use alloc::vec::Vec;
use core::{
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};
use wdk::println;
use wdk_sys::ntddk::{
    MmMapViewInSystemSpace, MmUnmapViewInSystemSpace, ObReferenceObjectByHandle,
    ObfDereferenceObject, RtlInitUnicodeString, ZwClose, ZwCreateSection, ZwOpenSection,
};
use wdk_sys::{
    HANDLE, KPROCESSOR_MODE, LARGE_INTEGER, NTSTATUS, OBJECT_ATTRIBUTES, PAGE_READWRITE, PSIZE_T,
    PVOID, SECTION_MAP_READ, SECTION_MAP_WRITE, SEC_COMMIT, STATUS_OBJECT_NAME_COLLISION,
    STATUS_SUCCESS, ULONG_PTR, UNICODE_STRING,
};

const HEADER_SIZE: usize = size_of::<Header>();

#[repr(C)]
struct Header {
    /// Next free byte for the producer (offset within the data region).
    head: AtomicU32,
    /// First unread byte for the consumer (offset within the data region).
    tail: AtomicU32,
    /// Number of dropped frames due to insufficient space.
    dropped: AtomicU32,
    /// Size in bytes of the data region (capacity).
    size: u32,
}

/// Mapped SECTION that provides a ring buffer in kernel space.
pub struct MemoryRing {
    pub(crate) section_handle: HANDLE,
    pub(crate) section_obj: *mut c_void,
    /// Base of the whole mapping (header at offset 0, data at `HEADER_SIZE`).
    pub(crate) base: *mut u8,
    /// Capacity in bytes of the data region.
    pub(crate) data_size: usize,
    /// Number of wrap‑around events observed by the producer (diagnostics only).
    wraps: AtomicU32,
}

impl MemoryRing {
    /// Creates (or opens) a named SECTION large enough for the header and the data region.
    ///
    /// Parameters:
    /// - `name`: NT path of the SECTION object to create or open.
    /// - `data_size`: number of bytes reserved for the data region (not including the header).
    ///
    /// Returns:
    /// - A `MemoryRing` with an open handle to the SECTION. The mapping is not established yet;
    ///   call [`map`] to map it in system space and initialize the header if needed.
    ///
    /// Safety considerations:
    /// - The SECTION name is copied by the object manager; the temporary UNICODE buffer may be
    ///   stack or heap backed.
    /// - A permissive security descriptor is used so user mode can open the SECTION.
    pub fn create(name: &str, data_size: usize) -> Result<Self, NTSTATUS> {
        // Convert name to UNICODE_STRING (lifetime local to this call).
        let mut uni = UNICODE_STRING::default();
        let utf16: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        unsafe { RtlInitUnicodeString(&mut uni, utf16.as_ptr()) };

        // Build a permissive SD; the object manager copies it when creating the object.
        let sd = unsafe { SecurityDescriptor::for_everyone()? };

        // OBJECT_ATTRIBUTES with name + security.
        let mut obj_attrs = OBJECT_ATTRIBUTES::default();
        unsafe {
            initialize_object_attributes(
                &mut obj_attrs,
                &mut uni,
                0,
                ptr::null_mut(),
                sd.as_ptr().cast(),
            );
        }

        // Total size for the SECTION backing store.
        let total = (HEADER_SIZE + data_size) as i64;
        let mut max_size = LARGE_INTEGER { QuadPart: total };

        // Attempt creation first; fall back to open on collision.
        let mut handle: HANDLE = ptr::null_mut();
        let status = unsafe {
            ZwCreateSection(
                &mut handle,
                SECTION_RW_MASK,
                &mut obj_attrs,
                &mut max_size,
                PAGE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(),
            )
        };

        println!(
            "[MemoryRing] name=\"{name}\", total_size=0x{:X}, ZwCreateSection={:#X}, handle={:p}",
            HEADER_SIZE + data_size,
            status,
            handle
        );

        drop(sd); // SD and name were copied by the object manager.

        match status {
            STATUS_SUCCESS => {
                println!("[MemoryRing] Created new section \"{name}\"");
            }
            STATUS_OBJECT_NAME_COLLISION => {
                let open_status =
                    unsafe { ZwOpenSection(&mut handle, SECTION_RW_MASK, &mut obj_attrs) };
                println!(
                    "[MemoryRing] Open existing section \"{name}\", ZwOpenSection={:#X}, handle={:p}",
                    open_status, handle
                );
                if open_status != STATUS_SUCCESS {
                    return Err(open_status);
                }
            }
            err => {
                println!("[MemoryRing] ZwCreateSection failed: {err:#X}");
                return Err(err);
            }
        }

        Ok(Self {
            section_handle: handle,
            section_obj: ptr::null_mut(),
            base: ptr::null_mut(),
            data_size,
            wraps: AtomicU32::new(0),
        })
    }

    /// Maps the SECTION in system space and initializes the header if it is uninitialized.
    ///
    /// Returns:
    /// - `Ok(())` on success, with `base` and `section_obj` set.
    /// - An NTSTATUS error from `ObReferenceObjectByHandle` or `MmMapViewInSystemSpace` otherwise.
    ///
    /// Notes:
    /// - If an older mapping already initialized the header with a different capacity, the header
    ///   is reset to the current capacity to keep producer/consumer in sync.
    pub fn map(&mut self) -> Result<(), NTSTATUS> {
        // Translate the section handle to a referenced object.
        let mut section_obj: PVOID = ptr::null_mut();
        let status = unsafe {
            ObReferenceObjectByHandle(
                self.section_handle,
                SECTION_MAP_READ | SECTION_MAP_WRITE,
                core::ptr::null_mut(), // `MmSectionObjectType` could be used if exposed
                0 as KPROCESSOR_MODE,  // KernelMode
                &mut section_obj,
                core::ptr::null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            println!("[MemoryRing] ObReferenceObjectByHandle failed: {status:#X}");
            return Err(status);
        }
        println!("[MemoryRing] Section object referenced: {section_obj:p}");

        // Map the entire region [Header + data] into system space.
        let mut base_address: PVOID = ptr::null_mut();
        let requested: usize = HEADER_SIZE + self.data_size;

        // `PSIZE_T` in bindings is `*mut ULONG_PTR`.
        let mut view_size: ULONG_PTR = requested as ULONG_PTR;

        let map_status =
            unsafe { MmMapViewInSystemSpace(section_obj, &mut base_address, &mut view_size as PSIZE_T) };
        if map_status != STATUS_SUCCESS {
            println!(
                "[MemoryRing] MmMapViewInSystemSpace failed: {map_status:#X} (requested=0x{:X})",
                requested
            );
            unsafe { ObfDereferenceObject(section_obj) };
            return Err(map_status);
        }

        println!(
            "[MemoryRing] Mapped at {base_address:p}, view_size=0x{:X} (requested=0x{:X})",
            view_size, requested
        );

        self.section_obj = section_obj;
        self.base = base_address as *mut u8;

        // Initialize or validate the header.
        let hdr = unsafe { &mut *(self.base as *mut Header) };
        let head0 = hdr.head.load(Ordering::Relaxed);
        let tail0 = hdr.tail.load(Ordering::Relaxed);
        let size0 = hdr.size;

        let need_init = size0 != self.data_size as u32 || (head0 == 0 && tail0 == 0 && size0 == 0);
        if need_init {
            hdr.head.store(0, Ordering::Relaxed);
            hdr.tail.store(0, Ordering::Relaxed);
            hdr.dropped.store(0, Ordering::Relaxed);
            hdr.size = self.data_size as u32;
            println!(
                "[MemoryRing] Header initialized: cap={} (old size={})",
                self.data_size, size0
            );
        } else {
            println!(
                "[MemoryRing] Header preserved: cap={} head={} tail={} drops={}",
                self.data_size,
                head0,
                tail0,
                hdr.dropped.load(Ordering::Relaxed)
            );
        }

        // The kernel may round mapping size up. Warn only if smaller than requested.
        if (view_size as usize) < requested {
            println!(
                "[MemoryRing] WARNING: mapped size (0x{:X}) < requested (0x{:X})",
                view_size, requested
            );
        }

        Ok(())
    }

    /// Pushes a frame `[u32 len_le][payload]` with natural wrap‑around.
    ///
    /// Drops the frame if there is not enough free space. A frame that cannot fit in an empty
    /// ring (`4 + payload.len() > capacity`) is also dropped and counted.
    ///
    /// Parameters:
    /// - `payload`: bytes to be appended as a single frame
    ///
    /// Safety:
    /// - Safe to call from callback contexts as long as they run at PASSIVE_LEVEL, which is the
    ///   case for our current callbacks. The function uses only non‑paged memory.
    pub fn push_bytes(&self, payload: &[u8]) {
        // If we are already unmapped (e.g., unload racing), just drop silently.
        if self.base.is_null() {
            return;
        }

        // Shared header view.
        let header = unsafe { &*(self.base as *const Header) };
        let cap = self.data_size;
        let payload_len = payload.len();
        let frame_total = 4 + payload_len;

        // Never fits even on an empty ring.
        if frame_total > cap {
            header.dropped.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "ring-trace")]
            println!(
                "[MemoryRing] drop(too-large): payload={} frame={} cap={}",
                payload_len, frame_total, cap
            );
            return;
        }

        // Load cursors. `tail` with Acquire to see consumer progress before committing.
        let head = header.head.load(Ordering::Relaxed) as usize;
        let tail = header.tail.load(Ordering::Acquire) as usize;

        // Compute free space prior to writing.
        let used_before = if head >= tail {
            head - tail
        } else {
            cap - (tail - head)
        };
        let free_before = cap - used_before;

        if free_before < frame_total {
            header.dropped.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "ring-trace")]
            println!(
                "[MemoryRing] drop(no-space): need={} free_before={} head={} tail={} used={} cap={}",
                frame_total, free_before, head, tail, used_before, cap
            );
            return;
        }

        // Copy helper that writes `len` bytes starting at `off` with wrap‑around.
        #[inline(always)]
        unsafe fn copy_circular(r: &MemoryRing, mut off: usize, src: *const u8, len: usize) {
            if len == 0 {
                return;
            }
            let cap = r.data_size;
            let to_end = cap - off;
            let first = core::cmp::min(len, to_end);
            core::ptr::copy_nonoverlapping(src, r.data_ptr(off), first);
            let rem = len - first;
            if rem != 0 {
                core::ptr::copy_nonoverlapping(src.add(first), r.data_ptr(0), rem);
            }
        }

        // Write the length prefix (LE), possibly split across the end.
        let len_le = (payload_len as u32).to_le_bytes();
        unsafe { copy_circular(self, head, len_le.as_ptr(), 4) };

        // Write the payload, possibly split.
        let after_len = (head + 4) % cap;
        unsafe { copy_circular(self, after_len, payload.as_ptr(), payload_len) };

        // Compute and publish the new head.
        let new_head = (head + frame_total) % cap;

        // Diagnostics: track whether this push crossed the end.
        let did_wrap = head + frame_total >= cap;
        let wraps_total = if did_wrap {
            self.wraps.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.wraps.load(Ordering::Relaxed)
        };

        // Publish the new head with Release so the consumer that observes head also sees payload.
        header.head.store(new_head as u32, Ordering::Release);

        // Optional trace (expensive, guarded).
        #[cfg(feature = "ring-trace")]
        {
            let used_after = if new_head >= tail {
                new_head - tail
            } else {
                cap - (tail - new_head)
            };
            let free_after = cap - used_after;

            println!(
                "[MemoryRing] push: payload={} frame={} cap={} head={}→{} tail={} wrap={} wraps={} \
                 free_before={} free_after={}",
                payload_len,
                frame_total,
                cap,
                head,
                new_head,
                tail,
                did_wrap as u8,
                wraps_total,
                free_before,
                free_after
            );
        }
    }

    #[inline]
    fn data_ptr(&self, offset: usize) -> *mut u8 {
        // Data region starts right after the header.
        unsafe { self.base.add(HEADER_SIZE + offset) }
    }
}

impl Drop for MemoryRing {
    fn drop(&mut self) {
        // Unmap, dereference and close in reverse order of acquisition.
        if !self.base.is_null() {
            println!("[MemoryRing] Unmapping base {:p}", self.base);
            unsafe { MmUnmapViewInSystemSpace(self.base as _) };
            self.base = ptr::null_mut();
        }
        if !self.section_obj.is_null() {
            println!("[MemoryRing] Dereferencing section object {:p}", self.section_obj);
            unsafe { ObfDereferenceObject(self.section_obj) };
            self.section_obj = ptr::null_mut();
        }
        if !self.section_handle.is_null() {
            println!("[MemoryRing] Closing section handle {:p}", self.section_handle);
            unsafe { ZwClose(self.section_handle) };
            self.section_handle = ptr::null_mut();
        }
    }
}
