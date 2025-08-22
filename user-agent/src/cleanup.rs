//! Console cleanup orchestration for Windows console apps.
//!
//! This module installs a Console Control Handler to catch:
//!   - CTRL_C_EVENT (Ctrl+C)
//!   - CTRL_CLOSE_EVENT (console window closed by the user)
//!
//! On those events it triggers a single-shot cleanup function that should:
//!   - Send your pre-unload IOCTL to the driver (unregister callbacks, quiesce, etc.).
//!   - Return quickly (the OS may allow ~5s on close; do not block in the handler).
//!
//! Design notes:
//!   - The handler must not block: we spawn a thread to run the cleanup.
//!   - The cleanup is idempotent (runs once even if multiple events arrive).
//!   - `TerminateProcess` / forced “End Task” will not invoke this path; plan driver robustness accordingly.
//!   - Avoid calling `std::process::exit` without calling `trigger()` first: `Drop` will be skipped.

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
};

/// Shared state referenced by the OS handler.
struct CleanupInner {
    /// Ensures the cleanup runs only once.
    fired: AtomicBool,
    /// The cleanup routine to execute. Must be fast and resilient.
    cleanup: Arc<dyn Fn() + Send + Sync + 'static>,
}

impl CleanupInner {
    /// Triggers cleanup once and only once; does the work on a background thread.
    fn fire_once(&self) {
        if !self.fired.swap(true, Ordering::SeqCst) {
            let f = Arc::clone(&self.cleanup);
            // Run on a separate thread to keep the handler non-blocking.
            thread::spawn(move || {
                log::info!("ConsoleCleanup: running cleanup routine…");
                (f)();
                log::info!("ConsoleCleanup: cleanup completed.");
            });
        }
    }
}

/// Process-wide state visible to the console handler.
static CLEANUP_STATE: OnceLock<Arc<CleanupInner>> = OnceLock::new();

/// Actual handler invoked by the OS. Must be minimal and return quickly.
///
/// Return value:
///   - non-zero: event handled
///   - zero: not handled
unsafe extern "system" fn console_handler(ctrl_type: u32) -> i32 {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_CLOSE_EVENT => {
            if let Some(state) = CLEANUP_STATE.get() {
                state.fire_once();
            }
            // Signal that we handled the event; the OS will continue termination flow.
            1
        }
        _ => 0,
    }
}

/// Public façade that manages handler registration and exposes trigger/status.
pub struct ConsoleCleanup {
    state: Arc<CleanupInner>,
}

impl ConsoleCleanup {
    /// Registers the console handler and sets the cleanup routine.
    ///
    /// # Parameters
    /// - `cleanup_fn`: a fast, non-blocking routine that sends your pre-unload IOCTL.
    ///
    /// # Panics
    /// Panics if `SetConsoleCtrlHandler` fails.
    pub fn new<F>(cleanup_fn: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        let inner = Arc::new(CleanupInner {
            fired: AtomicBool::new(false),
            cleanup: Arc::new(cleanup_fn),
        });

        // Publish global state once (per-process). If already set, reuse it.
        let state = CLEANUP_STATE.get_or_init(|| Arc::clone(&inner)).clone();

        unsafe {
            // Add our handler. Pass non-zero to add.
            let ok = SetConsoleCtrlHandler(Some(console_handler), 1);
            if ok == 0 {
                // Convert to panic with a meaningful message.
                panic!("SetConsoleCtrlHandler failed (GetLastError may provide details).");
            }
        }

        log::debug!("ConsoleCleanup: handler installed.");
        Self { state }
    }

    /// Manually trigger cleanup (idempotent).
    ///
    /// Useful before `std::process::exit` or when exiting voluntarily.
    pub fn trigger(&self) {
        self.state.fire_once();
    }

    /// Returns whether the cleanup has been triggered already.
    pub fn was_triggered(&self) -> bool {
        self.state.fired.load(Ordering::SeqCst)
    }
}

impl Drop for ConsoleCleanup {
    fn drop(&mut self) {
        // Best-effort: if not triggered yet, trigger now.
        if !self.was_triggered() {
            log::debug!("ConsoleCleanup: triggering cleanup from Drop.");
            self.state.fire_once();
        }
        // We do not deregister the handler; process exit is imminent anyway.
    }
}



