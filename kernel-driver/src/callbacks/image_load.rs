//! Image‑load callback wiring. Converts the kernel notification into a compact event and relies on
//! `filters::should_emit_image_load` to drop high‑churn system activity before publishing to the
//! shared ring. This keeps the hot path small and deterministic.

use crate::callbacks::common::push_event;
use crate::callbacks::filters::should_emit_image_load;
use crate::utils::uni_to_string;
use alloc::string::String;
use shared::events::callbacks::ImageLoadEvent;
use wdk_sys::{
    ntddk::{PsRemoveLoadImageNotifyRoutine, PsSetLoadImageNotifyRoutine},
    HANDLE, IMAGE_INFO, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
};

/// Register the image‑load notification routine.
///
/// Parameters:
/// - none
///
/// Returns:
/// - `Ok(())` on success (`STATUS_SUCCESS`)
/// - `Err(status)` with the kernel `NTSTATUS` on failure
#[inline]
pub fn register() -> Result<(), NTSTATUS> {
    let status = unsafe { PsSetLoadImageNotifyRoutine(Some(load_image_notify)) };
    if status == STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

/// Unregister the image‑load notification routine.
///
/// Parameters:
/// - none
///
/// Returns:
/// - `Ok(())` on success (`STATUS_SUCCESS`)
/// - `Err(status)` with the kernel `NTSTATUS` on failure
#[inline]
pub fn unregister() -> Result<(), NTSTATUS> {
    let status = unsafe { PsRemoveLoadImageNotifyRoutine(Some(load_image_notify)) };
    if status == STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

/// Kernel callback for image mappings (DLLs and executables).
///
/// Parameters (from the kernel):
/// - `full_image_name`: optional `UNICODE_STRING` with the file path (can be empty but non‑null)
/// - `process_id`: target process receiving the mapping
/// - `image_info`: details such as base address and size
///
/// Safety:
/// - Invoked by the kernel at PASSIVE_LEVEL. Pointers are valid only for the duration of the call.
/// - Do not store raw pointers from here; copy what is needed and return quickly.
///
/// Notes:
/// - The callback may fire for system images very frequently. Filtering is applied before emitting.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn load_image_notify(
    full_image_name: *mut UNICODE_STRING,
    process_id: HANDLE,
    image_info: *mut IMAGE_INFO,
) {
    if full_image_name.is_null() || image_info.is_null() {
        return;
    }

    // Convert path and capture the minimal fields we need before returning to the kernel.
    let path: String = uni_to_string(&*full_image_name);
    let info = &*image_info;
    let image_base = info.ImageBase as u64;
    let image_size = info.ImageSize as u32;
    let pid = process_id as u32;

    // Cut common noise early; see filters.rs for the rationale and tunables.
    if !should_emit_image_load(pid, &path, image_size) {
        return;
    }

    let evt = ImageLoadEvent {
        image_base,
        image_size,
        full_image_name: path,
        process_id: pid,
    };
    push_event(evt.into());
}
