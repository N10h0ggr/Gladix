// communications/ioctl_dispatch.rs
//! IOCTL dispatchers and thin CREATE/CLOSE handlers.
//!
//! User mode requests a handle to the shared SECTION; we open it by name with `ZwOpenSection`.
//! Because dispatch runs in the caller’s context, the handle is created directly in the caller’s
//! handle table and no duplication is necessary. The device object still owns the ring lifetime,
//! which is validated via the device extension on entry.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::{mem, ptr};
use wdk::println;

use crate::utils::{get_current_irp_stack_location, initialize_object_attributes, UnicodeString};
use crate::callback_guard;
use crate::callbacks;
use crate::DeviceExtension;
use shared::constants::{
    IOCTL_GLADIX_GET_SECTION_HANDLE, 
    IOCTL_GLADIX_SEND_HOOK_EVENT,
    IOCTL_GLADIX_UNREGISTER_CALLBACKS,
    KERNEL_SHARED_SECTION_NAME
};

use wdk_sys::ntddk::{ExAcquireRundownProtection, ExReleaseRundownProtection, IofCompleteRequest, ZwOpenSection, KeGetCurrentIrql};
use wdk_sys::{ACCESS_MASK, CCHAR, DEVICE_OBJECT, HANDLE, IRP, NTSTATUS, PASSIVE_LEVEL};
use wdk_sys::{OBJECT_ATTRIBUTES, STATUS_DEVICE_NOT_READY};
use wdk_sys::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_INVALID_DEVICE_STATE};

const IO_NO_INCREMENT: CCHAR = 0;

/// Helper to complete an IRP and return the same status.
///
/// Parameters:
/// - `irp`: IRP to complete (may be null for defensive programming)
/// - `status`: NTSTATUS to set on the IRP
/// - `information`: number of bytes returned to the caller
///
/// Returns:
/// - `status` (convenience so call sites can `return complete(...)`)
#[inline]
fn complete(irp: *mut IRP, status: NTSTATUS, information: u64) -> NTSTATUS {
    if !irp.is_null() {
        unsafe {
            (*irp).IoStatus.__bindgen_anon_1.Status = status;
            (*irp).IoStatus.Information = information;
            IofCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }
    status
}

/// Minimal `IRP_MJ_CREATE` handler. No per-handle state is kept.
///
/// Returns:
/// - `STATUS_SUCCESS` unconditionally
///
/// Safety:
/// - Called by the I/O manager in arbitrary process context. Pointers must be valid.
pub unsafe extern "C" fn dispatch_create(
    _dev: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    // This path is typically noisy; avoid logging unless debugging handshakes.
    complete(irp, STATUS_SUCCESS, 0)
}

/// Minimal `IRP_MJ_CLOSE` handler.
///
/// Returns:
/// - `STATUS_SUCCESS` unconditionally
///
/// Safety:
/// - Called by the I/O manager in arbitrary process context. Pointers must be valid.
pub unsafe extern "C" fn dispatch_close(
    _dev: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    complete(irp, STATUS_SUCCESS, 0)
}

/// `IRP_MJ_DEVICE_CONTROL` dispatcher.
///
/// Parameters:
/// - `device_object`: target device
/// - `irp`: request packet with buffered I/O
///
/// Returns:
/// - `STATUS_SUCCESS` on handled codes
/// - An appropriate failure status on errors or unsupported codes
///
/// Notes:
/// - We validate the device extension implicitly by requiring a non-null device object.
/// - The only supported IOCTL opens a named SECTION in the caller’s handle table.
///
/// Safety:
/// - Pointers must be valid for the duration of the call; the I/O manager guarantees this.
pub unsafe extern "C" fn dispatch_device_control(
    device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    if device_object.is_null() || irp.is_null() {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }

    let stack = match get_current_irp_stack_location(irp) {
        Ok(s) => s,
        Err(st) => {
            return complete(irp, st, 0);
        }
    };

    // Sanity check the device extension; it owns the ring mapping lifetime.
    if (*device_object).DeviceExtension.is_null() {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }

    let code     = (*stack).Parameters.DeviceIoControl.IoControlCode;
    let in_len   = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;
    let out_len  = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
    let sysbuf   = (*irp).AssociatedIrp.SystemBuffer as *mut u8;

    match code {
        IOCTL_GLADIX_GET_SECTION_HANDLE   => handle_get_section_handle(irp, sysbuf, out_len),
        IOCTL_GLADIX_SEND_HOOK_EVENT      => handle_send_hook_event(device_object, irp, sysbuf, in_len),
        IOCTL_GLADIX_UNREGISTER_CALLBACKS => handle_prepare_unload(device_object, irp),
        _ => {
            println!("[IOCTL] Unsupported code=0x{:08X}", code);
            complete(irp, STATUS_INVALID_PARAMETER, 0)
        }
    }
}


/// Implements `IOCTL_GLADIX_GET_SECTION_HANDLE`.
///
/// Opens a handle to the named SECTION using `ZwOpenSection` in the caller’s context, then writes
/// the resulting HANDLE into the system buffer.
///
/// Parameters:
/// - `irp`: request packet
/// - `system_buffer`: output buffer (buffered I/O); must hold a HANDLE
/// - `out_len`: size of the output buffer in bytes
///
/// Returns:
/// - `STATUS_SUCCESS` and writes `HANDLE` on success
/// - `STATUS_BUFFER_TOO_SMALL` if the output buffer cannot hold the handle
/// - Propagates failures from `ZwOpenSection`
///
/// Safety:
/// - The IRP and buffer pointers are managed by the I/O manager and valid for the call. We only
///   write a `HANDLE` into the provided buffer.
fn handle_get_section_handle(
    irp: *mut IRP,
    system_buffer: *mut u8,
    out_len: usize,
) -> NTSTATUS {
    if system_buffer.is_null() || out_len < mem::size_of::<HANDLE>() {
        return complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    // Build `UNICODE_STRING` and `OBJECT_ATTRIBUTES` for the kernel path.
    let mut us_name = UnicodeString::new(KERNEL_SHARED_SECTION_NAME);
    let mut oa = OBJECT_ATTRIBUTES::default();
    unsafe {
        // OBJ_CASE_INSENSITIVE (0x40) would be acceptable, but the name is canonical already.
        initialize_object_attributes(
            &mut oa,
            &mut *us_name.as_mut_ptr(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }

    // Read+write mapping is sufficient for the user-mode consumer of the ring.
    const DESIRED: ACCESS_MASK =
        (wdk_sys::SECTION_MAP_READ | wdk_sys::SECTION_MAP_WRITE) as ACCESS_MASK;

    let mut user_handle: HANDLE = ptr::null_mut();
    let status = unsafe { ZwOpenSection(&mut user_handle, DESIRED, &mut oa) };

    // Single concise log to confirm handshake; occurs at most once per user process startup.
    println!(
        "[IOCTL] GET_SECTION_HANDLE: ZwOpenSection(name=\"{}\") => {:#X}, handle={:p}",
        KERNEL_SHARED_SECTION_NAME, status, user_handle
    );

    if status != STATUS_SUCCESS || user_handle.is_null() {
        return complete(irp, status, 0);
    }

    unsafe { ptr::write(system_buffer.cast::<HANDLE>(), user_handle) };
    complete(irp, STATUS_SUCCESS, mem::size_of::<HANDLE>() as u64)
}


/// Handles IOCTL_GLADIX_SEND_HOOK_EVENT (METHOD_BUFFERED).
///
/// Parameters:
/// - `device_object`: the target device, used to reach the DeviceExtension.
/// - `irp`: request to complete.
/// - `sysbuf`: METHOD_BUFFERED system buffer pointer (input payload).
/// - `in_len`: input length reported by the I/O manager.
///
/// Returns:
/// - `STATUS_SUCCESS` and sets `Information` to the number of bytes accepted on success.
/// - Valid NTSTATUS error codes on failure.
///
/// Safety:
/// - `device_object`, `irp`, `sysbuf` must be valid for the duration per I/O manager contract.
pub unsafe fn handle_send_hook_event(
    device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
    sysbuf: *mut u8,
    in_len: usize,
) -> NTSTATUS {

    if sysbuf.is_null() || in_len == 0 {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }

    // Reach the device extension; it owns the shared ring and the unload rundown gate.
    let dev_ext = (*device_object).DeviceExtension as *mut crate::DeviceExtension;
    if dev_ext.is_null() {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }

    // Gate writes while the device is being torn down.
    let acquired = unsafe { ExAcquireRundownProtection(&mut (*dev_ext).rundown) };
    if acquired == 0 {
        // Another thread is tearing down the device; do not accept new data.
        return complete(irp, STATUS_DEVICE_NOT_READY, 0);
    }

    // SAFETY: `sysbuf` is valid for `in_len` bytes under METHOD_BUFFERED.
    let bytes = unsafe { core::slice::from_raw_parts(sysbuf, in_len) };
    (*dev_ext).ring.push_bytes(bytes);

    unsafe { ExReleaseRundownProtection(&mut (*dev_ext).rundown) };

    complete(irp, STATUS_SUCCESS, in_len as u64)
}

/// Handle IOCTL_GLADIX_PREPARE_UNLOAD to begin race-safe driver teardown.
///
/// This disables new callback entries via `ExRundownCompleted`, unregisters all registered
/// callbacks (registry, image-load, process), and returns `STATUS_SUCCESS`. It does not delete
/// the device or symbolic link; those remain under `DriverUnload`.
///
/// Parameters:
/// - `device_object`: target device object for this driver
/// - `irp`:          current IRP (must be valid and buffered)
///
/// Returns:
/// - `STATUS_SUCCESS` on successful execution
/// - `STATUS_INVALID_DEVICE_STATE` if not running at PASSIVE_LEVEL
///
/// Safety:
/// - Must be called at PASSIVE_LEVEL
/// - Assumes `device_object` is either null or a valid DEVICE_OBJECT with a DeviceExtension.
/// - Uses `complete()` to finalize the IRP; caller must not touch it afterward.
unsafe fn handle_prepare_unload(
    device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    if KeGetCurrentIrql() != PASSIVE_LEVEL as u8 {
        return complete(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }

    if device_object.is_null() {
        println!("[IOCTL] No device object! Trying to unregister callbacks anyways...");
        callbacks::unregister_all();
        return complete(irp, STATUS_SUCCESS, 0);
    }

    let dev_ext = (*device_object).DeviceExtension as *mut DeviceExtension;
    if dev_ext.is_null() {
        println!("[IOCTL] No device extension! Trying to unregister callbacks anyways...");
        callbacks::unregister_all();
        return complete(irp, STATUS_SUCCESS, 0);
    }

    let mask = (*dev_ext).cb_mask;

    if mask.reg {
        match callbacks::registry::unregister() {
            Ok(()) => println!("[IOCTL] registry callback unregistered."),
            Err(st) => println!("[IOCTL] registry callback unregistration failed: {:#X}", st),
        }
    }
    if mask.img {
        match callbacks::image_load::unregister() {
            Ok(()) => println!("[IOCTL] image-load callback unregistered."),
            Err(st) => println!("[IOCTL] image-load callback unregistration failed: {:#X}", st),
        }
    }
    if mask.proc {
        match callbacks::process::unregister() {
            Ok(()) => println!("[IOCTL] process callback unregistered."),
            Err(st) => println!("[IOCTL] process callback unregistration failed: {:#X}", st),
        }
    }

    complete(irp, STATUS_SUCCESS, 0)
}
