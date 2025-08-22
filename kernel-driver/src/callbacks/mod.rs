//! Central hub for registering and unregistering the driver’s callback families. Registration is
//! transactional: if any step fails, previously registered callbacks are rolled back and the global
//! ring pointer is cleared so `DriverEntry` can abort safely without leaving dangling hooks.
//!
//! Rationale:
//! - This module owns the orchestration and rollback policy for all callback families.
//! - It accepts a borrowed ring and stashes a raw pointer via `common::set_ring`; the ring is owned
//!   by the driver’s device extension and outlives the callbacks.
//! - One callback family requires access to the driver object; the pointer is threaded through
//!   `register_all` and passed to the specific registration routine.

pub mod common;
pub mod process;
pub mod image_load;
pub mod registry;
pub mod filters;
pub mod callback_guard;

use crate::communications::MemoryRing;
use common::{clear_ring, set_ring};
use wdk::println;
use wdk_sys::{NTSTATUS, PVOID};

/// Tracks which callback families registered successfully so we can undo work in reverse order.
///
/// This is intentionally simple and copyable; unload paths do not depend on heap state.
#[derive(Copy, Clone, Default)]
pub struct CallbackMask {
    pub proc: bool,
    pub img:  bool,
    pub reg:  bool,
}

impl CallbackMask {
    #[inline]
    pub fn any(self) -> bool {
        self.proc || self.img || self.reg
    }
}

/// Register all callback families in a fixed order. On failure, this function rolls back any
/// successful registrations, clears the global ring pointer, and returns the failing status.
///
/// Parameters:
/// - `ring`: shared-memory ring used by callbacks to emit telemetry events.
/// - `driver_ptr`: pointer to the `DRIVER_OBJECT` received in `DriverEntry`. One callback family
///   requires it; pass the exact pointer you were given.
///
/// Returns:
/// - `Ok(mask)` where `mask` indicates what was registered when everything succeeds.
/// - `Err(status)` if any registration fails; prior registrations are already undone.
///
/// Precautions:
/// - Call exactly once during initialization, before any events may be emitted.
/// - The caller must ensure `ring` outlives the callbacks (device extension lifetime).
pub fn register_all(ring: &MemoryRing, driver_ptr: PVOID) -> Result<CallbackMask, NTSTATUS> {
    set_ring(ring);
    let mut mask = CallbackMask::default();

    // Process notify
    match process::register() {
        Ok(()) => {
            mask.proc = true;
            println!("[Callbacks] PsSetCreateProcessNotifyRoutineEx OK");
        }
        Err(st) => {
            println!("[Callbacks] Process register failed: 0x{:08X}", st);
            clear_ring();
            return Err(st);
        }
    }

    // Image-load notify
    match image_load::register() {
        Ok(()) => {
            mask.img = true;
            println!("[Callbacks] PsSetLoadImageNotifyRoutine OK");
        }
        Err(st) => {
            println!("[Callbacks] Image load register failed: 0x{:08X}", st);
            let _ = process::unregister(); // best-effort rollback
            clear_ring();
            return Err(st);
        }
    }

    // Registry notify (requires the driver object pointer)
    // match registry::register(driver_ptr) {
    //     Ok(()) => {
    //         mask.reg = true;
    //         println!("[Callbacks] Registry callback OK");
    //     }
    //     Err(st) => {
    //         println!("[Callbacks] Registry register failed: 0x{:08X}", st);
    //         let _ = image_load::unregister();
    //         let _ = process::unregister();
    //         clear_ring();
    //         return Err(st);
    //     }
    // }

    Ok(mask)
}

/// Unregister callback families according to `mask` in reverse registration order and clear the
/// global ring pointer.
///
/// Parameters:
/// - `mask`: flags indicating which families were registered.
///
/// Returns:
/// - Nothing. Best-effort unregistration; failures are ignored.
///
/// Precautions:
/// - Safe to call during unload paths; idempotency is handled by the underlying WDK calls.
pub fn unregister_mask(mask: CallbackMask) {
    if mask.reg {
        let _ = registry::unregister();
    }
    if mask.img {
        let _ = image_load::unregister();
    }
    if mask.proc {
        let _ = process::unregister();
    }
    clear_ring();
}

/// Convenience helper that attempts to unregister every callback family and clears the ring even if
/// some calls fail. Useful when no `CallbackMask` is tracked.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Intended for fallback/teardown code paths where granular state is not available.
// TODO: Consider routing all teardown through `unregister_mask` and a stored mask to keep one path.
pub fn unregister_all() {
    let _ = registry::unregister();
    let _ = image_load::unregister();
    let _ = process::unregister();
    clear_ring();
}
