//! callbacks/registry.rs
//!
//! Registry telemetry wiring. We register a single `CmRegisterCallbackEx` routine and only
//! publish `RegNtPreSetValueKey` events, which are the most actionable for configuration and
//! persistence changes. Names for key objects are resolved with `ObQueryNameString` because the
//! `REG_*_KEY_INFORMATION` structs do not embed a `UNICODE_STRING` path.

extern crate alloc;

use crate::callbacks::common::push_event;
use crate::callbacks::filters::should_emit_registry_setvalue;
use crate::utils::uni_to_string;

use alloc::string::String;
use alloc::vec::Vec;
use core::{mem, ptr, slice};

use shared::events::callbacks::{OperationType, RegistryEvent};

use wdk_sys::{
    ntddk::{
        CmRegisterCallbackEx, CmUnRegisterCallback, ExAllocatePool2, ExFreePoolWithTag,
        ObQueryNameString, PsGetCurrentProcessId,
    },
    NTSTATUS, OBJECT_NAME_INFORMATION, POOL_FLAG_PAGED, PVOID, REG_NOTIFY_CLASS,
    REG_SET_VALUE_KEY_INFORMATION, SIZE_T, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, UNICODE_STRING, _REG_NOTIFY_CLASS as NC,
};

/// Cookie returned by `CmRegisterCallbackEx`. Required for unregistering.
static mut COOKIE: wdk_sys::LARGE_INTEGER = wdk_sys::LARGE_INTEGER { QuadPart: 0 };

/// Altitude used to order registry callbacks. Static storage avoids lifetime questions around
/// the `UNICODE_STRING` buffer. The trailing NUL is intentional; `Length` excludes it.
static ALTITUDE_W: &[u16] = &[
    '3' as u16, '2' as u16, '1' as u16, '0' as u16, '0' as u16, '4' as u16, '.' as u16, '4' as u16,
    '2' as u16, 0,
];

/// Register the registry-change callback.
///
/// Parameters:
/// - `driver_ptr`: opaque `PVOID` that must be the `DriverObject` from `DriverEntry`
///                 (required by `CmRegisterCallbackEx`).
///
/// Returns:
/// - `Ok(())` on success
/// - `Err(status)` with the kernel `NTSTATUS` on failure
///
/// Notes:
/// - The callback is lean and only emits `PreSetValue` to keep noise under control.
/// - If you add more classes, reconsider the filtering policy in `filters.rs`.
#[inline]
pub fn register(driver_ptr: PVOID) -> Result<(), NTSTATUS> {
    // Build a counted string that points at our static buffer. The CM copies altitude metadata
    // during registration; using static storage keeps things straightforward across reloads.
    let altitude = UNICODE_STRING {
        Length: ((ALTITUDE_W.len() - 1) * 2) as u16,     // bytes, without NUL
        MaximumLength: (ALTITUDE_W.len() * 2) as u16,     // bytes, with space for NUL
        Buffer: ALTITUDE_W.as_ptr() as *mut u16,          // writable PWSTR per signature
    };

    let cookie_ptr = unsafe { &raw mut COOKIE as *mut _ };

    let status = unsafe {
        CmRegisterCallbackEx(
            Some(registry_callback),
            &altitude as *const UNICODE_STRING,
            driver_ptr,          // required: DriverObject
            ptr::null_mut(),     // optional context (unused)
            cookie_ptr,          // out cookie
            ptr::null_mut(),     // Reserved
        )
    };

    if status == STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

/// Unregister the registry-change callback.
///
/// Parameters:
/// - none
///
/// Returns:
/// - `Ok(())` on success
/// - `Err(status)` with the kernel `NTSTATUS` on failure
#[inline]
pub fn unregister() -> Result<(), NTSTATUS> {
    let status = unsafe { CmUnRegisterCallback(COOKIE) };
    if status == STATUS_SUCCESS {
        unsafe { COOKIE.QuadPart = 0 };
        Ok(())
    } else {
        Err(status)
    }
}

/// Registry callback routine. We only act on `RegNtPreSetValueKey` to capture modifications right
/// before they hit the hive. All other classes are ignored to reduce churn.
///
/// Parameters (kernel):
/// - `_context`: user context pointer from registration (unused)
/// - `notify_ptr`: integer-encoded `REG_NOTIFY_CLASS` (passed as a pointer-sized value)
/// - `argument`: class-specific structure; for `PreSetValue` it is `REG_SET_VALUE_KEY_INFORMATION`
///
/// Safety:
/// - Invoked by the kernel; pointers are valid only for the duration of the call.
/// - The routine must not block; copy what is needed and return quickly.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn registry_callback(
    _context: PVOID,
    notify_ptr: *mut core::ffi::c_void,
    argument: *mut core::ffi::c_void,
) -> NTSTATUS {
    // Convert the pointer-sized discriminator into our enum.
    let notify_class: REG_NOTIFY_CLASS = {
        let raw = notify_ptr as usize as u32;
        mem::transmute::<u32, REG_NOTIFY_CLASS>(raw)
    };

    if notify_class != NC::RegNtPreSetValueKey {
        return STATUS_SUCCESS;
    }

    // PreSetValue payload: object handle, optional value name, raw new data.
    let info = &*(argument as *const REG_SET_VALUE_KEY_INFORMATION);

    // Key path must be resolved via the object manager; the info block does not carry the string.
    let key_path = query_object_name(info.Object)
        .unwrap_or_else(|_| String::from("<unknown>"));

    // Value name can be absent; keep it best-effort for filtering.
    let value_name = uni_to_string(info.ValueName);
    let pid = PsGetCurrentProcessId() as u32;

    // Early drop to keep the ring quiet unless the write is interesting for our product.
    if !should_emit_registry_setvalue(
        &key_path,
        if value_name.is_empty() { None } else { Some(&value_name) },
    ) {
        return STATUS_SUCCESS;
    }

    // Copy new data; type and old value are out of scope for now.
    let new_buf: Vec<u8> = if info.DataSize > 0 && !info.Data.is_null() {
        let data_slice = slice::from_raw_parts(info.Data as *const u8, info.DataSize as usize);
        Vec::from(data_slice)
    } else {
        Vec::new()
    };

    let evt = RegistryEvent {
        key_path,
        op_type: OperationType::Modify as i32,
        old_value: Vec::new(), // not available at PreSetValue stage
        new_value: new_buf,
        process_id: pid,
    };
    push_event(evt.into());

    STATUS_SUCCESS
}

/// Resolve the NT object name (e.g., `\REGISTRY\MACHINE\...`) for a given registry key object.
///
/// Strategy is the standard two-call pattern: query for the required size, allocate exactly that
/// size from paged pool, then query the name. Callers should expect empty names for some transient
/// objects and treat them as best-effort telemetry.
///
/// Parameters:
/// - `object`: key object pointer accepted by `ObQueryNameString`
///
/// Returns:
/// - `Ok(String)` with the NT path, or an empty string if unnamed
/// - `Err(status)` on failure to query or allocate
///
/// Safety:
/// - `object` must refer to a valid object. Function must run at PASSIVE_LEVEL because it uses
///   paged pool.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn query_object_name(object: PVOID) -> Result<String, NTSTATUS> {
    // First call to learn the size.
    let mut needed: u32 = 0;
    let st0 = ObQueryNameString(object, ptr::null_mut(), 0, &mut needed);
    if st0 != STATUS_INFO_LENGTH_MISMATCH && st0 != STATUS_SUCCESS {
        return Err(st0);
    }
    if needed == 0 {
        return Ok(String::new());
    }

    // Allocate the exact buffer. Registry callbacks run at PASSIVE_LEVEL.
    const TAG: u32 = u32::from_le_bytes(*b"ONAM");
    let buf = ExAllocatePool2(POOL_FLAG_PAGED, needed as SIZE_T, TAG);
    if buf.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }

    // Second call to retrieve the name.
    let mut retlen: u32 = 0;
    let st = ObQueryNameString(object, buf as *mut OBJECT_NAME_INFORMATION, needed, &mut retlen);
    if st != STATUS_SUCCESS {
        ExFreePoolWithTag(buf, TAG);
        return Err(st);
    }

    // Convert UNICODE_STRING to UTF‑8 String.
    let oni = &*(buf as *const OBJECT_NAME_INFORMATION);
    let len = (oni.Name.Length / 2) as usize;
    let slice16 = slice::from_raw_parts(oni.Name.Buffer, len);
    let s = String::from_utf16_lossy(slice16);

    ExFreePoolWithTag(buf, TAG);
    Ok(s)
}
