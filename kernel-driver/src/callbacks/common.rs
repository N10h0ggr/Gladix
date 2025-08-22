//! Global access to the kernel–user shared ring and a tiny helper to frame and push events.
//!
//! Design
//! -------
//! Callbacks execute on arbitrary threads long after `DriverEntry` returns, so they cannot carry
//! a borrowed reference to the ring. We publish a single raw pointer to the ring that lives in
//! the device extension and guard its lifetime with the unload/rundown sequence in this driver.
//!
//! Memory ordering
//! ---------------
//! The ring pointer is stored with `Release` and read with `Acquire`. This is sufficient to make
//! the initialized `MemoryRing` fields visible to readers once the pointer becomes non‐null. We
//! clear the pointer with `Release` during unload to stop new pushes early. Callbacks themselves
//! are protected via `callback_guard` so teardown cannot race with in‑flight uses.

use crate::communications::MemoryRing;
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};
use shared::events::Event;
use prost::Message;

/// Single global pointer to the ring (allocated inside the device extension).
///
/// Safety/lifetime is enforced by the driver’s initialization/unload order:
/// - `set_ring()` is called after the device extension is fully initialized.
/// - Callbacks are registered only after `set_ring()`.
/// - Unload calls `unregister_*`, waits for rundown, then `clear_ring()`, then drops the extension.
static RING_PTR: AtomicPtr<MemoryRing> = AtomicPtr::new(ptr::null_mut());

/// Publish the ring pointer so callbacks can push events.
///
/// Parameters:
/// - `ring`: reference to the ring stored inside the device extension.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Must be called before registering any callbacks. Call exactly once per driver instance.
pub fn set_ring(ring: &MemoryRing) {
    // Publish to readers; fields initialized before this store become visible after an Acquire load.
    RING_PTR.store(ring as *const _ as *mut _, Ordering::Release);
}

/// Clear the published pointer to prevent new pushes after unload begins.
///
/// Parameters:
/// - None.
///
/// Returns:
/// - Nothing.
///
/// Precautions:
/// - Call during teardown after callbacks are unregistered and rundown has drained.
pub fn clear_ring() {
    RING_PTR.store(ptr::null_mut(), Ordering::Release);
}

/// Encode an event to protobuf and push it into the shared ring.
///
/// Parameters:
/// - `ev`: event to serialize and enqueue.
///
/// Returns:
/// - Nothing. If the ring is not available or encoding fails, the call is a no‑op.
///
/// Precautions:
/// - This function does not perform synchronization itself; callers should already be inside a
///   rundown‑protected section (callbacks do this via `callback_guard::enter()`).
pub fn push_event(ev: Event) {
    // Acquire the pointer; null means not initialized or already torn down.
    let ring_ptr = RING_PTR.load(Ordering::Acquire);
    let Some(ring) = (unsafe { ring_ptr.as_ref() }) else {
        return;
    };

    // Serialize; allocate on demand. This is a hot path, but simple and robust.
    let mut buf = Vec::new();
    if ev.encode(&mut buf).is_err() {
        return;
    }

    ring.push_bytes(&buf);
}
