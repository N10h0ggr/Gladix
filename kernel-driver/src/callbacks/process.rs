//! Process notifications wiring. We publish a compact event only for process creation and rely on
//! `filters::should_emit_process_create` to discard high‑churn or low‑value events. Exit events are
//! intentionally ignored to keep the telemetry budget focused on creation time, which is the most
//! useful point for correlation and detection.

use crate::callbacks::common::push_event;
use crate::callbacks::filters::should_emit_process_create;
use crate::utils::uni_to_string;
use shared::events::callbacks::ProcessEvent;
use wdk_sys::{
    ntddk::PsSetCreateProcessNotifyRoutineEx, HANDLE, NTSTATUS, PEPROCESS, PS_CREATE_NOTIFY_INFO,
    STATUS_SUCCESS,
};

/// Register the process‑create notification routine.
///
/// Parameters:
/// - none
///
/// Returns:
/// - `Ok(())` on success (`STATUS_SUCCESS`)
/// - `Err(status)` with the kernel `NTSTATUS` on failure
#[inline]
pub fn register() -> Result<(), NTSTATUS> {
    // Second parameter: 0 -> register
    let status = unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0) };
    if status == STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

/// Unregister the process‑create notification routine.
///
/// Parameters:
/// - none
///
/// Returns:
/// - `Ok(())` on success (`STATUS_SUCCESS`)
/// - `Err(status)` with the kernel `NTSTATUS` on failure
#[inline]
pub fn unregister() -> Result<(), NTSTATUS> {
    // Second parameter: 1 -> unregister
    let status = unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1) };
    if status == STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

/// Kernel callback for process lifecycle.
/// We only emit events for creation; exits arrive with `info_ptr == NULL`.
///
/// Parameters (from the kernel):
/// - `process`: EPROCESS of the target
/// - `_pid`: historic field, do not rely on it; use `info_ptr` and `process`
/// - `info_ptr`: non‑null for creation, null for exit
///
/// Safety:
/// - Invoked by the kernel at PASSIVE_LEVEL for the Ex variant.
/// - Pointers are valid only for the duration of the call; copy what is needed and return quickly.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn process_notify(
    process: PEPROCESS,
    _pid: HANDLE,
    info_ptr: *mut PS_CREATE_NOTIFY_INFO,
) {
    // Exit notifications are signaled with a null info block. We ignore them by design.
    if info_ptr.is_null() {
        return;
    }

    let info = &*info_ptr;

    // Capture minimal, self‑contained data. Do not persist kernel pointers.
    // PS_CREATE_NOTIFY_INFO fields can be empty; `uni_to_string` handles null/zero‑length safely.
    let pid = wdk_sys::ntddk::PsGetProcessId(process) as u32;
    let ppid = info.ParentProcessId as u32;
    let image_path = uni_to_string(info.ImageFileName);
    let cmdline = uni_to_string(info.CommandLine);

    // Drop low‑value events early to avoid pressure on the ring.
    if !should_emit_process_create(pid, &image_path) {
        return;
    }

    let evt = ProcessEvent {
        pid,
        ppid,
        image_path,
        cmdline,
    };
    push_event(evt.into());
}
