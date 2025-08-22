//! Small wrapper around the kernel’s rundown-protection primitives to make callback
//! registration/unregistration race-free. A single global pointer holds the driver’s
//! `EX_RUNDOWN_REF` (allocated inside the device extension). Callbacks acquire the protection
//! on entry and release it on exit; unload first blocks new acquisitions, then waits for
//! in‑flight callbacks to drain.
//!
//! Additionally, a lightweight counter is kept for diagnostics so unload logs can report how
//! many callbacks are currently active.

use core::{
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};
use wdk_sys::{
    ntddk::{
        ExAcquireRundownProtection, ExInitializeRundownProtection, ExReleaseRundownProtection,
        ExRundownCompleted, ExWaitForRundownProtectionRelease,
    },
    EX_RUNDOWN_REF,
};

/// Global pointer to the driver’s rundown object stored in the device extension.
///
/// The pointer is written during `DriverEntry` after the device extension is constructed and
/// cleared during unload. All loads/stores use Acquire/Release to serialize with Ex* calls.
static RUNDOWN_PTR: AtomicPtr<EX_RUNDOWN_REF> = AtomicPtr::new(ptr::null_mut());

/// Best‑effort count of live callback entries currently holding the rundown.
///
/// Used only for debugging/telemetry; not part of the synchronization protocol.
static ACTIVE: AtomicU32 = AtomicU32::new(0);

/// Publish the rundown pointer so callbacks can acquire protection.
///
/// Parameters:
/// - `p`: address of the `EX_RUNDOWN_REF` inside the device extension.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Call exactly once during driver initialization, before registering any callbacks.
pub fn set_rundown_ptr(p: *mut EX_RUNDOWN_REF) {
    RUNDOWN_PTR.store(p, Ordering::Release);
}

/// Clear the published rundown pointer.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Call during teardown after all callbacks are unregistered and drained.
pub fn clear_rundown_ptr() {
    RUNDOWN_PTR.store(ptr::null_mut(), Ordering::Release);
}

/// Initialize a fresh rundown object.
///
/// Parameters:
/// - `r`: pointer to uninitialized `EX_RUNDOWN_REF`.
///
/// Returns:
/// - Nothing.
///
/// Safety:
/// - `r` must be a valid, writable pointer that remains alive for the driver’s lifetime or until
///   rundown completes in unload.
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn init_rundown(r: *mut EX_RUNDOWN_REF) {
    ExInitializeRundownProtection(r);
}

/// Transition the rundown into “completed” state to block new acquires.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Invoke at the beginning of the unload path, before unregistering callbacks, so no new
///   entries can start while teardown proceeds.
pub fn begin_unload() {
    if let Some(p) = unsafe { RUNDOWN_PTR.load(Ordering::Acquire).as_mut() } {
        unsafe { ExRundownCompleted(p) };
    }
}

/// Wait until all existing holders have released the rundown and the object is idle.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Call after `begin_unload`. This blocks until all in‑flight callbacks have exited their
///   critical sections.
pub fn wait_for_zero() {
    if let Some(p) = unsafe { RUNDOWN_PTR.load(Ordering::Acquire).as_mut() } {
        unsafe { ExWaitForRundownProtectionRelease(p) };
    }
}

#[inline]
#[allow(unsafe_op_in_unsafe_fn)]
fn acquire() -> bool {
    let p = RUNDOWN_PTR.load(Ordering::Acquire);
    if p.is_null() {
        return false;
    }
    // ExAcquireRundownProtection returns non‑zero on success.
    if unsafe { ExAcquireRundownProtection(p) } != 0 {
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[inline]
#[allow(unsafe_op_in_unsafe_fn)]
fn release() {
    let p = RUNDOWN_PTR.load(Ordering::Acquire);
    if !p.is_null() {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        unsafe { ExReleaseRundownProtection(p) };
    }
}

/// RAII scope guard that holds rundown protection for the lifetime of the value.
///
/// Dropping the guard releases the protection. Construct this at the very start of each callback
/// and keep it alive until after the last access to driver state that requires protection.
pub struct Scope {
    pub acquired: bool,
}

impl Drop for Scope {
    fn drop(&mut self) {
        if self.acquired {
            release();
        }
    }
}

/// Enter a protected region for the current callback and return a guard.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - `Scope` which, when dropped, releases the protection. If acquisition fails because unload
///   has begun, `Scope.acquired` is `false` and no protection is held.
///
/// Precautions:
/// - Always bind the returned value to a local (e.g., `let _g = callback_guard::enter();`) so it
///   lives for the entire critical region.
#[inline]
pub fn enter() -> Scope {
    Scope { acquired: acquire() }
}

/// Current number of callbacks that are inside a protected region (best effort).
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Count of active holders tracked by this module.
///
/// Precautions:
/// - Intended for logging/diagnostics; not a synchronization primitive.
pub fn active_count() -> u32 {
    ACTIVE.load(Ordering::Relaxed)
}
