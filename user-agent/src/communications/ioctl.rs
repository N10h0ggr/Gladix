//! Thin wrappers to talk to the kernel driver via IOCTL.
//!
//! The driver brokers a handle to a named SECTION into this process. Opening the device and asking
//! the kernel to call `ZwOpenSection` in our context avoids Global\ name resolution issues and MIC
//! (integrity level) / session pitfalls.

use log::{debug, error, info};
use shared::constants::{ALT_DEVICE_SYMBOLIC_NAME, IOCTL_GLADIX_GET_SECTION_HANDLE, IOCTL_GLADIX_UNREGISTER_CALLBACKS};
use std::{ffi::OsStr, io, mem::size_of, os::windows::ffi::OsStrExt, ptr};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// RAII wrapper for a device handle. Closes the handle on drop.
struct Device(HANDLE);

impl Device {
    /// Open the device interface exposed by the driver.
    ///
    /// The path must be a DOS device path (e.g. `\\.\Gladix`), which typically comes from
    /// `ALT_DEVICE_SYMBOLIC_NAME`.
    ///
    /// # Errors
    /// Returns an `io::Error` if `CreateFileW` fails or returns `INVALID_HANDLE_VALUE`.
    fn open(path: &str) -> io::Result<Self> {
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();

        // Request read/write; driver uses minimal access checks on the file object itself.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Foundation::GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            error!("CreateFileW({path}) failed: {err}");
            return Err(err);
        }

        // This happens once per session; leave it as informational.
        info!("Device opened: {path}");
        Ok(Device(handle))
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Ask the driver to broker a SECTION handle into this process.
///
/// The driver calls `ZwOpenSection` from kernel mode while running in the caller's process
/// context, so the resulting `HANDLE` is created directly in this process' handle table.
/// No duplication is required.
///
/// # Returns
/// A user‑mode `HANDLE` to the shared SECTION, suitable for mapping with `MapViewOfFile`.
///
/// # Errors
/// Returns an `io::Error` if the device cannot be opened or if the IOCTL fails. The error is
/// based on `GetLastError()` when available.
///
pub fn request_section_handle() -> io::Result<HANDLE> {
    let dev = Device::open(ALT_DEVICE_SYMBOLIC_NAME)?;

    let mut out_handle: HANDLE = ptr::null_mut();
    let mut bytes: u32 = 0;

    unsafe {
        let ok = DeviceIoControl(
            dev.0,
            IOCTL_GLADIX_GET_SECTION_HANDLE,
            ptr::null_mut(),
            0,
            &mut out_handle as *mut _ as *mut _,
            size_of::<HANDLE>() as u32,
            &mut bytes as *mut _,
            ptr::null_mut(),
        );

        debug!(
            "DeviceIoControl(IOCTL_GLADIX_GET_SECTION_HANDLE) ok={} bytes={} handle={:p}",
            ok, bytes, out_handle
        );

        // Validate both the BOOL return and the contract on the output size.
        if ok == 0 || out_handle.is_null() || bytes != size_of::<HANDLE>() as u32 {
            let code = GetLastError();
            let err = if code != 0 {
                io::Error::from_raw_os_error(code as i32)
            } else {
                io::Error::last_os_error()
            };
            error!("DeviceIoControl(IOCTL_GLADIX_GET_SECTION_HANDLE) failed: {err}");
            return Err(err);
        }
    }

    // Happens once and is useful to see the brokered handle value during bring‑up.
    info!("Received section handle {:p} from driver", out_handle);
    Ok(out_handle)
}


/// Ask the driver to begin the pre-unload sequence (quiesce + unregister callbacks).
///
/// Contract:
/// - METHOD_BUFFERED with no input/output buffers.
/// - The driver should complete the IRP with `IoStatus.Information = 0`.
///
/// Behavior:
/// - This call is synchronous (no OVERLAPPED), so the thread blocks until the driver completes.
/// - Intended to be called right before process termination (e.g., Ctrl+C / console close),
///   or explicitly during app shutdown.
///
/// # Errors
/// Returns an `io::Error` if the device cannot be opened or if the IOCTL fails. The error is
/// derived from `GetLastError()` when available.
pub fn send_unregister_callbacks_ioctl() -> io::Result<()> {

    let dev = Device::open(ALT_DEVICE_SYMBOLIC_NAME)?;
    let mut bytes: u32 = 0;

    unsafe {
        let ok = DeviceIoControl(
            dev.0,                              // device handle
            IOCTL_GLADIX_UNREGISTER_CALLBACKS, // control code
            ptr::null_mut(),                    // in buffer
            0,                                  // in size
            ptr::null_mut(),                    // out buffer
            0,                                  // out size
            &mut bytes as *mut _,               // bytes returned
            ptr::null_mut(),                    // OVERLAPPED (none => synchronous)
        );

        debug!(
            "DeviceIoControl(IOCTL_GLADIX_UNREGISTER_CALLBACKS) ok={} bytes={}",
            ok, bytes
        );

        if ok == 0 {
            // Map the OS error code to io::Error.
            let code = GetLastError();
            let err = if code != 0 {
                io::Error::from_raw_os_error(code as i32)
            } else {
                io::Error::last_os_error()
            };
            error!(
                "DeviceIoControl(IOCTL_GLADIX_UNREGISTER_CALLBACKS) failed: {}",
                err
            );
            return Err(err);
        }
    }
    
    info!("Driver pre-unload sequence requested successfully.");
    Ok(())
}
