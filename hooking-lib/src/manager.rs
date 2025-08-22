use crate::hooks::Hook;
use std::ffi::c_void;


/// A single hook specification describing:
/// 1. `dll`: the target DLL name (e.g., `"ntdll.dll"`).
/// 2. `func`: the target function name inside that DLL (e.g., `"NtOpenProcess"`).
/// 3. `detour`: pointer to your detour function (cast to `*const u8`).
/// 4. `orig_ptr`: a mutable pointer to a `*const c_void` where the “gateway” address will be stored
///    so the detour can call the original syscall stub.
///
/// In practice, you create one `HookEntry` per function you want to intercept. For example:
///
/// ```rust
/// static mut ORIG_NTOPEN: *const c_void = std::ptr::null();
///
/// let entry = HookEntry {
///     dll:      "ntdll.dll",
///     func:     "NtOpenProcess",
///     detour:   MyNtOpenProcessHook as *const u8,
///     orig_ptr: &mut ORIG_NTOPEN,
/// };
/// ```
#[derive(Clone, Copy)]
pub struct HookEntry {
    /// Name of the DLL containing the target function.
    pub dll: &'static str,
    /// Name of the function to hook (must exactly match the exported name).
    pub func: &'static str,
    /// Pointer to your detour function (cast to `*const u8`).
    pub detour: *const u8,
    /// Address of a `static mut *const c_void` where we’ll store the gateway pointer.
    pub orig_ptr: *mut *const c_void,
}

unsafe impl Send for HookEntry {}
unsafe impl Sync for HookEntry {}

/// Manages a collection of hook specifications (`spec`) and the corresponding
/// “live” `Hook` objects after installation.
///
/// Typical usage:
///
/// 1. Create a new manager:  
///    ```rust
///    let mut mgr = HookManager::new();
///    ```
///
/// 2. Add one or more `HookEntry` definitions:  
///    ```rust
///    mgr.add(HookEntry {
///        dll:      "ntdll.dll",
///        func:     "NtOpenProcess",
///        detour:   MyNtOpenProcessHook as *const u8,
///        orig_ptr: &mut ORIG_NTOPEN,
///    });
///    ```
///
/// 3. Install all hooks in one go:  
///    ```rust
///    mgr.install_all();
///    ```
///
/// 4. When you’re done (e.g., DLL unload), remove all installed hooks:  
///    ```rust
///    mgr.remove_all();
///    ```
pub struct HookManager {
    /// A list of all hook specifications you’ve added but not yet installed.
    spec: Vec<HookEntry>,
    /// Once installed, each `Hook` is stored here so we can later remove it.
    live: Vec<Hook>,
}

impl HookManager {
    /// Creates a new, empty `HookManager` with no specs and no live hooks.
    ///
    /// ```rust
    /// let mut mgr = HookManager::new();
    /// assert!(mgr.spec.is_empty());
    /// assert!(mgr.live.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            spec: Vec::new(),
            live: Vec::new(),
        }
    }

    /// Adds a hook specification to the internal list. This does not install it immediately.
    ///
    /// ### Arguments
    ///
    /// * `e` – a `HookEntry` describing one function to intercept.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let mut mgr = HookManager::new();
    /// mgr.add(HookEntry {
    ///     dll:      "ntdll.dll",
    ///     func:     "NtReadVirtualMemory",
    ///     detour:   MyNtReadVirtualMemoryHook as *const u8,
    ///     orig_ptr: &mut ORIG_NTREADVM,
    /// });
    /// ```
    pub fn add(&mut self, e: HookEntry) {
        self.spec.push(e);
    }

    /// Installs every hook in the `spec` list, in the order they were added.
    ///
    /// For each `HookEntry`:
    /// 1. Calls `Hook::new(entry.dll, entry.func, entry.detour)`.
    /// 2. Stores the returned gateway pointer into `*entry.orig_ptr`, so the detour can call
    ///    the original syscall.
    /// 3. Keeps the `Hook` object alive in `self.live`.
    /// 4. Prints a log message on success: `"[EDR] installed {dll}!{func}"`.
    ///
    /// # Panics / Error Handling
    ///
    /// This method uses `unwrap()` on the result of `Hook::new()`, so if any single hook fails
    /// to be created (e.g., DLL not found, function not found, or memory protection failure),
    /// the process will panic. In a production setting, you may want to capture and log errors
    /// instead of unwrapping.
    ///
    /// # Safety
    ///
    /// - Each call to `Hook::new(...)` performs raw pointer writes and page‐protection changes.
    /// - All installed hooks will remain active until `remove_all()` is called.
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut mgr = HookManager::new();
    /// mgr.add(HookEntry { /* … */ });
    /// mgr.add(HookEntry { /* … */ });
    /// mgr.install_all();
    /// // Now every function in `spec` is patched.
    /// ```
    pub fn install_all(&mut self) {
        for e in &self.spec {
            unsafe {
                // Create the Hook, which patches the target function’s first bytes.
                let h = Hook::new(e.dll, e.func, e.detour).unwrap();
                // Save the gateway pointer so the detour can call the real syscall.
                *e.orig_ptr = h.gateway();
                // Keep the Hook alive so `remove()` can later restore the original bytes.
                self.live.push(h);
            }
            println!("[EDR] installed {}!{}", e.dll, e.func);
        }
    }

    /// Removes every installed hook by iterating `self.live` and calling `remove()` on each `Hook`,
    /// then clears `self.live`. After this returns, all original stubs have been restored.
    ///
    /// # Safety
    ///
    /// - Each `Hook::remove()` will perform raw writes and restore page protections.
    /// - Once removed, those `Hook` instances are no longer valid and should not be used again.
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut mgr = HookManager::new();
    /// mgr.add(HookEntry { /* … */ });
    /// mgr.install_all();
    /// mgr.remove_all();
    /// ```
    pub fn uninstall_all(&mut self) {
        for h in &self.live {
            unsafe {
                h.remove();
            }
        }
        self.live.clear();
    }
}
