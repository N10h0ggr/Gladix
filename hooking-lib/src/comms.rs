// comms.rs
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows::core::{Error, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

use shared::constants::{ALT_DEVICE_SYMBOLIC_NAME, IOCTL_GLADIX_SEND_HOOK_EVENT};

static DEVICE_HANDLE_RAW: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Try to open the EDR driver device once.  On error, we return Err and
/// let the caller log it.
fn get_device_handle() -> Result<HANDLE, Error> {
    let raw = DEVICE_HANDLE_RAW.load(Ordering::SeqCst);
    if !raw.is_null() {
        return Ok(HANDLE(raw));
    }

    // Build a null-terminated wide string from DEVICE_SYMBOLIC_NAME
    let mut wide: Vec<u16> = ALT_DEVICE_SYMBOLIC_NAME.encode_utf16().collect();
    wide.push(0);

    // This is allowed to fail if the driver isn't loaded yet.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };
    let new_raw = handle.0 as *mut _;

    // Race‐free install if still null
    match DEVICE_HANDLE_RAW.compare_exchange(
        null_mut(),
        new_raw,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => Ok(handle),
        Err(existing) => {
            // somebody else won the race
            unsafe { CloseHandle(handle).ok(); }
            Ok(HANDLE(existing as _))
        }
    }
}

/// Send `buffer` down to the driver via IOCTL_SEND_HOOK_EVENT,
/// logging *all* errors along the way.
pub fn send_to_driver(buffer: &[u8]) {

    let device = match get_device_handle() {
        Ok(h) => h,
        Err(e) => return
    };

    let mut bytes_returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            device,
            IOCTL_GLADIX_SEND_HOOK_EVENT,
            Some(buffer.as_ptr() as *const c_void),
            buffer.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
}
