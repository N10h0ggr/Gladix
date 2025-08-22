#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_unsafe)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod hooks;
mod manager;
mod detours;
mod comms;
mod call_guard;

use std::thread;
use windows::Win32::{
    Foundation::{HMODULE, HINSTANCE, HANDLE},
    System::{
        LibraryLoader::{DisableThreadLibraryCalls, GetModuleHandleA},
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
    },
};


/// Windows‐recommended pattern: do minimal work under loader lock, spawn a thread
/// for heavy lifting. We install only “safe” hooks here (no heap‐critical APIs).
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: u32, _: *mut ()) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => unsafe {
            // Prevent thread notifications—we don’t need them.
            DisableThreadLibraryCalls(HMODULE::from(hinst)).ok();

            thread::spawn(|| {
                detours::install_all_hooks()
                    .expect("failed to install hooks");
            });
        }

        DLL_PROCESS_DETACH => {
            // On unload, restore all hooks
            let _ = detours::uninstall_all_hooks();
        }

        _ => {}
    }
    true
}

