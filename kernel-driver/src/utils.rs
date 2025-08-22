//! utils.rs
//!
//! Small, focused helpers for common Windows kernel tasks used across the driver.
//! These utilities avoid re‑implementing fragile boilerplate around UNICODE_STRING,
//! IRP stack access, and OBJECT_ATTRIBUTES initialization.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    mem::{self, MaybeUninit},
    ptr, slice,
};
use wdk_sys::{
    ntddk::RtlInitUnicodeString, // use the official import to avoid a manual extern
    HANDLE, IRP, NTSTATUS, OBJECT_ATTRIBUTES, PIO_STACK_LOCATION, STATUS_INVALID_PARAMETER,
    UNICODE_STRING,
};

/// Owns a `UNICODE_STRING` and its backing UTF‑16 buffer.
///
/// Windows APIs often expect a `UNICODE_STRING` whose `Buffer` remains valid for the
/// duration of the call. This type keeps the buffer alive for as long as the struct
/// is alive, preventing dangling pointers.
///
/// The string is NUL‑terminated, although many kernel routines do not require the
/// trailing NUL; having it makes interop simpler and harmless for typical use.
///
/// Cloning is not provided intentionally to avoid accidental copies of large buffers.
pub struct UnicodeString {
    raw: UNICODE_STRING,
    buffer: Vec<u16>,
}

impl UnicodeString {
    /// Creates a `UNICODE_STRING` backed by a NUL‑terminated UTF‑16 buffer.
    ///
    /// The internal buffer lifetime is tied to this object, so taking raw pointers via
    /// `as_ptr`/`as_mut_ptr` is safe as long as the `UnicodeString` instance outlives
    /// the API call.
    pub fn new(s: &str) -> Self {
        let mut buffer: Vec<u16> = s.encode_utf16().collect();
        buffer.push(0); // make it NUL‑terminated for APIs that require it

        let mut raw = MaybeUninit::<UNICODE_STRING>::zeroed();
        unsafe {
            RtlInitUnicodeString(raw.as_mut_ptr(), buffer.as_ptr());
            Self {
                raw: raw.assume_init(),
                buffer,
            }
        }
    }

    /// Returns a const pointer to the inner `UNICODE_STRING`.
    #[inline]
    pub fn as_ptr(&self) -> *const UNICODE_STRING {
        &self.raw
    }

    /// Returns a mut pointer to the inner `UNICODE_STRING`.
    ///
    /// Useful for APIs that require `PUNICODE_STRING`.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut UNICODE_STRING {
        &mut self.raw
    }
}

/// Returns the current IRP stack location (`PIO_STACK_LOCATION`) for a given IRP.
///
/// This mirrors the WDK's `IoGetCurrentIrpStackLocation` logic using the IRP tail overlay
/// fields that bindgen generated for us.
///
/// # Parameters
/// - `irp`: pointer to a valid IRP.
///
/// # Returns
/// - `Ok(PIO_STACK_LOCATION)` on success.
/// - `Err(STATUS_INVALID_PARAMETER)` if the IRP looks malformed.
///
/// # Safety
/// The caller must guarantee `irp` is a valid pointer to an IRP allocated by the I/O manager.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn get_current_irp_stack_location(irp: *mut IRP) -> Result<PIO_STACK_LOCATION, NTSTATUS> {
    let curr = (*irp).CurrentLocation;
    let max = (*irp).StackCount + 1; // see WDK: CurrentLocation is 1‑based
    if curr == 0 || curr > max {
        return Err(STATUS_INVALID_PARAMETER);
    }

    // Matches the IRP layout in ntddk.h; bindgen exposes these anonymous unions/structs.
    let loc = (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation;

    Ok(loc)
}

/// Converts a kernel `UNICODE_STRING*` to an owned Rust `String`.
///
/// Lossy UTF‑16 decoding is used to be resilient to odd inputs; this is standard in
/// Windows drivers that log or forward paths and command lines.
///
/// # Parameters
/// - `uni`: pointer to a `UNICODE_STRING` (may be NULL).
///
/// # Returns
/// - An owned `String`. Returns an empty string if `uni` is NULL.
///
/// # Safety
/// `uni` must either be NULL or point to a valid `UNICODE_STRING` whose `Buffer` is readable
/// for `Length` bytes.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn uni_to_string(uni: *const UNICODE_STRING) -> String {
    if uni.is_null() {
        return String::new();
    }
    let uref = &*uni;
    let len = (uref.Length / 2) as usize; // Length is in bytes; UTF‑16 units are 2 bytes
    let slice = slice::from_raw_parts(uref.Buffer, len);
    String::from_utf16_lossy(slice)
}

/// Initializes an `OBJECT_ATTRIBUTES` structure with the given parameters.
///
/// This is a thin helper to avoid repetitive field assignments and to centralize the
/// initialization pattern used by Zw/Nt object APIs.
///
/// # Parameters
/// - `obj`: output structure to initialize.
/// - `name`: object name (may be empty if the API accepts a NULL name).
/// - `attributes`: OBJ_* flags (e.g., `OBJ_CASE_INSENSITIVE`).
/// - `root`: optional root handle for relative opens (NULL for absolute).
/// - `sd`: optional security descriptor pointer (may be NULL).
///
/// # Safety
/// Pointers must be valid for write/read as appropriate. This does not retain any of the
/// provided pointers; the caller owns their lifetimes. Many Zw/Nt APIs expect `name` to
/// remain valid for the duration of the call.
pub unsafe fn initialize_object_attributes(
    obj: &mut OBJECT_ATTRIBUTES,
    name: &mut UNICODE_STRING,
    attributes: u32,
    root: HANDLE,
    sd: *mut core::ffi::c_void,
) {
    obj.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    obj.RootDirectory = root;
    obj.Attributes = attributes;
    obj.ObjectName = name;
    obj.SecurityDescriptor = sd;
    obj.SecurityQualityOfService = ptr::null_mut();
}

/// Returns the pseudo‑handle for the current process (`NtCurrentProcess()`).
///
/// This value can be passed to many Zw/Nt calls that accept a process handle and is
/// valid only in the current process context.
///
/// Provided here to avoid relying on macros that do not translate directly to Rust bindings.
#[inline]
pub fn nt_current_process() -> HANDLE {
    (-1isize) as HANDLE
}
