
// Re-entrancy guard that works inside the loader-lock.
// --------------------------------------------------
//   • Avoids Rust `thread_local!` → no NULL TLS issues.
//   • Uses a single Win32 TLS slot for all hooks.
//   • Stores a dummy non-NULL pointer (0x1) as “I’m inside the hook”.
//   • Cleared automatically with RAII (`Drop`).
//
// Safety notes
// ------------
// - We never dereference the pointer stored in TLS.
// - No heap allocations while the guard is held.
// - Only raw Win32 calls: safe even during `DllMain` or `LdrpSnapModule`.

#![allow(unsafe_code)]

use core::ffi::c_void;
use once_cell::sync::Lazy;
use std::{marker::PhantomData, ptr};
use windows::Win32::System::Threading::{TlsAlloc, TlsGetValue, TlsSetValue};

/// TLS slot index allocated once per process.
///
/// `Lazy` ensures `TlsAlloc()` runs the first time the DLL is referenced,
/// *after* the PE has been mapped but still **before** any hook executes.
static TLS_SLOT: Lazy<u32> = Lazy::new(|| unsafe { TlsAlloc() });

/// Dummy non-NULL pointer used as the “inside hook” flag.
///
/// 0x1 is convenient and guaranteed to be invalid/alignment-agnostic; we never
/// dereference it, merely compare against NULL.
const SENTINEL: *const c_void = 1_usize as *const c_void;

/// RAII object returned by [`CallGuard::enter`]
pub struct CallGuard {
    _private: PhantomData<*const ()>,
}

impl CallGuard {
    /// Try to enter the protected section.
    ///
    /// Returns `Some(CallGuard)` on first entry (continue with detour code)
    /// or `None` if this thread is already executing inside the hook.
    #[inline(always)]
    pub fn enter() -> Option<Self> {
        unsafe {
            let idx = *TLS_SLOT;

            // If the slot already holds a non-NULL value, we’re re-entering.
            if !TlsGetValue(idx).is_null() {
                return None;
            }

            // First time on this thread – mark as “inside”.
            //
            // `TlsSetValue` uses `Option<*const c_void>` (None = NULL).
            if TlsSetValue(idx, Some(SENTINEL)).is_ok() {
                Some(Self {
                    _private: PhantomData,
                })
            } else {
                // Extremely unlikely, but if the slot can’t be set just bail
                // out and pretend we are re-entered to avoid recursion loops.
                None
            }
        }
    }
}

impl Drop for CallGuard {
    /// Clears the TLS flag so the thread can re-enter later.
    fn drop(&mut self) {
        unsafe {
            // Ignore failure: worst case the flag remains set and we’ll
            // continue short-circuiting to the real API.
            let _ = TlsSetValue(*TLS_SLOT, None);
        }
    }
}
