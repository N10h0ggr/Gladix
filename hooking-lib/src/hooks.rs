//! Hot-patcher for ntdll Nt* APIs.
//!
//! Overwrites the first 13 (x64) or 7 (x86) bytes of a target Nt* function with a jump to a “detour”.
//! Builds a small RWX “gateway” buffer that re-implements the original syscall stub in a clean 11‐byte
//! (x64) or 10‐byte (x86) sequence. This allows the detour to call the real syscall via the gateway
//! rather than the overwritten bytes.

use std::{ffi::c_void, ptr, slice};
use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::FlushInstructionCache,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
        },
    },
};

#[cfg(target_pointer_width = "64")]
const PATCH_LEN: usize = 13; // mov r10,imm64 ; jmp r10
#[cfg(target_pointer_width = "32")]
const PATCH_LEN: usize = 7;  // mov eax,imm32 ; jmp eax

#[cfg(target_pointer_width = "64")]
const GATEWAY_LEN: usize = 11; // 4C 8B D1 B8 <id> 0F 05 C3
#[cfg(target_pointer_width = "32")]
const GATEWAY_LEN: usize = 10; // mov eax,<id> ; int 2E ; ret

/// SAFETY: We know that `Hook` only contains raw pointers and
/// a POD `PAGE_PROTECTION_FLAGS` It does *not* own any non-`'static` data.
/// Therefore it is safe to send it across threads or share references to it.
unsafe impl Send for Hook {}
unsafe impl Sync for Hook {}

/// A low‐level hook object for patching Nt* functions in ntdll.dll:
///
/// 1. Saves the first `PATCH_LEN` bytes of the target function.
/// 2. Builds a small “gateway” in RWX memory that contains a clean syscall stub.
/// 3. Overwrites the first `PATCH_LEN` bytes of the target with a jump to our `detour`.
/// 4. On `.remove()`, restores the original bytes and frees the gateway buffer.
/// 
pub struct Hook {
    /// Pointer to the first byte of the original target function.
    target: *mut u8,

    /// Pointer to our detour function (cast to `*const u8`).
    _detour: *const u8,

    /// Saved `PATCH_LEN` bytes from the original function, so we can restore them.
    saved: [u8; PATCH_LEN],

    /// RWX‐allocated buffer containing the reconstructed syscall stub.
    gateway: *mut u8,

    /// Original page protection flags before we made it RWX.
    old_protect: PAGE_PROTECTION_FLAGS,
}

impl Hook {
    /// Scans the first 20 bytes of the original stub for `mov eax,<imm32>` (opcode `0xB8`)
    /// and returns the 32‐bit immediate value as the syscall ID.
    ///
    /// # Safety
    /// - Caller must ensure `stub` points to at least 20 valid bytes from a real Nt* stub.
    unsafe fn extract_syscall_id(stub: &[u8]) -> u32 {
        // We look for the single‐byte opcode 0xB8 followed by a 4‐byte little‐endian ID.
        for w in stub.windows(5) {
            if w[0] == 0xB8 {
                return u32::from_le_bytes([w[1], w[2], w[3], w[4]]);
            }
        }
        0
    }

    /// Allocates a GATEWAY_LEN-byte RWX page, writes a minimal syscall stub into it, and returns
    /// the pointer. On x64:
    ///
    /// ```text
    ///   4C 8B D1          ; mov r10, rcx
    ///   B8 <id>           ; mov eax, <syscall id>
    ///   0F 05             ; syscall
    ///   C3                ; ret
    /// ```
    ///
    /// On x86:
    ///
    /// ```text
    ///   B8 <id>           ; mov eax, <syscall id>
    ///   CD 2E             ; int 2E
    ///   C3                ; ret
    /// ```
    ///
    /// # Safety
    /// - Caller must supply a valid `id` from `extract_syscall_id`.
    /// - The returned pointer must be `VirtualFree`d with `MEM_RELEASE` when no longer needed.
    unsafe fn make_gateway(id: u32) -> *mut u8 { unsafe {
        let gw = VirtualAlloc(
            None,
            GATEWAY_LEN,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        assert!(!gw.is_null(), "VirtualAlloc failed for gateway");

        #[cfg(target_pointer_width = "64")]
        {
            // Build x64 stub: mov r10, rcx; mov eax,<id>; syscall; ret
            let bytes: [u8; GATEWAY_LEN] = [
                0x4C, 0x8B, 0xD1,                    // mov r10, rcx
                0xB8,                                // mov eax, <id>
                (id & 0xFF)        as u8,
                ((id >> 8)  & 0xFF) as u8,
                ((id >> 16) & 0xFF) as u8,
                ((id >> 24) & 0xFF) as u8,
                0x0F, 0x05,                          // syscall
                0xC3,                                // ret
            ];
            ptr::copy_nonoverlapping(bytes.as_ptr(), gw, GATEWAY_LEN);
        }

        #[cfg(target_pointer_width = "32")]
        {
            // Build x86 stub: mov eax,<id>; int 2E; ret
            let bytes: [u8; GATEWAY_LEN] = [
                0xB8,                                // mov eax, <id>
                (id & 0xFF)        as u8,
                ((id >> 8)  & 0xFF) as u8,
                ((id >> 16) & 0xFF) as u8,
                ((id >> 24) & 0xFF) as u8,
                0xCD, 0x2E,                          // int 2E
                0xC3,                                // ret
            ];
            ptr::copy_nonoverlapping(bytes.as_ptr(), gw, GATEWAY_LEN);
        }

        gw
    }}

    /// Creates and installs a hook by:
    /// 1. Finding `func` inside `dll` via `GetModuleHandleA` + `GetProcAddress`.
    /// 2. Saving the first `PATCH_LEN` bytes of the original function.
    /// 3. Extracting the syscall ID from those saved bytes.
    /// 4. Allocating a “gateway” stub in RWX memory with a clean syscall sequence.
    /// 5. Changing the target page to RWX and patching its first `PATCH_LEN` bytes to a jump to `detour`.
    ///
    /// On success, returns a `Hook` that stores:
    /// - `target`: pointer to the patched function,
    /// - `detour`: the detour pointer you provided,
    /// - `saved`: the overwritten bytes for restoration,
    /// - `gateway`: pointer to the new syscall stub,
    /// - `old_protect`: the original page‐protection flags.
    ///
    /// # Arguments
    /// - `dll`: Name of the target DLL (e.g. `"ntdll.dll"`). Must not contain interior null bytes.
    /// - `func`: Name of the target function (e.g. `"NtOpenProcess"`). Must not contain interior null bytes.
    /// - `detour`: Pointer to your hook function cast to `*const u8`.
    ///
    /// # Returns
    /// - `Ok(Hook)` if everything succeeded.
    /// - `Err(String)` if DLL loading, function lookup, or memory protection failed.
    ///
    /// # Safety
    /// - This call performs raw pointer manipulation, page‐protection changes, and writes into
    ///   executable code. Caller must ensure the process truly has `dll` loaded and that `func` is valid.
    /// - The returned `Hook` must have `.remove()` called before dropping, or else the process
    ///   may crash if the overwritten bytes are never restored.
    pub unsafe fn new(dll: &str, func: &str, detour: *const u8) -> Result<Self, String> { unsafe {

        let c_dll_name = CString::new(dll).map_err(|e| format!("dll_name contains null: {e}"))?;
        let c_fn_name = CString::new(func).map_err(|e| format!("fn_name contains null: {e}"))?;
        
        let s_dll_name = PCSTR(c_dll_name.as_ptr() as *const u8);
        let s_fn_name = PCSTR(c_fn_name.as_ptr() as *const u8);
        
        let hmod = GetModuleHandleA(s_dll_name).map_err(|e| {
            format!("GetModuleHandleA(\"{}\") failed: {:?}", dll, e)
        })?;

        // Find the function’s address
        let target = GetProcAddress(hmod, s_fn_name).unwrap() as *mut u8;

        // Save the first PATCH_LEN bytes so we can restore them later
        let mut saved = [0u8; PATCH_LEN];
        ptr::copy_nonoverlapping(target, saved.as_mut_ptr(), PATCH_LEN);

        // Extract the syscall ID (we only need the first ~20 bytes to find “mov eax,<id>”)
        let id = Self::extract_syscall_id(slice::from_raw_parts(target, 20));

        if id == 0 {
            eprintln!("mov eax,<id> not found in {func}")
        }

        // Build a clean syscall stub in a newly allocated RWX buffer
        let gateway = Self::make_gateway(id);

        // Change page protection to RWX so we can write our patch
        let mut old = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(target as _, PATCH_LEN, PAGE_EXECUTE_READWRITE, &mut old)
            .map_err(|e| format!("VirtualProtect failed: {:?}", e))?;

        // Write the jump to our detour (x64 vs x86 differ)
        let mut patch = [0u8; PATCH_LEN];
        #[cfg(target_pointer_width = "64")]
        {
            // mov r10,<detour>
            patch[0] = 0x49;
            patch[1] = 0xBA;
            patch[2..10].copy_from_slice(&(detour as u64).to_le_bytes());
            // jmp r10
            patch[10] = 0x41;
            patch[11] = 0xFF;
            patch[12] = 0xE2;
        }
        #[cfg(target_pointer_width = "32")]
        {
            // mov eax,<detour>
            patch[0] = 0xB8;
            patch[1..5].copy_from_slice(&(detour as u32).to_le_bytes());
            // jmp eax
            patch[5] = 0xFF;
            patch[6] = 0xE0;
        }

        ptr::copy_nonoverlapping(patch.as_ptr(), target, PATCH_LEN);
        let _ = FlushInstructionCache(HANDLE(ptr::null_mut()), Some(target as _), PATCH_LEN);

        Ok(Self {
            target,
            _detour: detour,
            saved,
            gateway,
            old_protect: old,
        })
    }}

    /// Restores the original `PATCH_LEN` bytes at `target`, resets the original page protection,
    /// flushes the instruction cache, and frees the gateway buffer.
    ///
    /// # Safety
    /// - Must only be called on a `Hook` previously constructed with `Hook::new`.
    /// - After calling `remove()`, the `Hook` instance is no longer valid and must be dropped.
    pub unsafe fn remove(&self) { unsafe {

        let mut tmp = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(self.target as _, PATCH_LEN, PAGE_EXECUTE_READWRITE, &mut tmp)
            .unwrap();

        // Copy back the saved bytes
        ptr::copy_nonoverlapping(self.saved.as_ptr(), self.target, PATCH_LEN);
        
        VirtualProtect(self.target as _, PATCH_LEN, self.old_protect, &mut tmp).ok();

        let _ = FlushInstructionCache(HANDLE(ptr::null_mut()), Some(self.target as _), PATCH_LEN);

        // Free the gateway buffer
        VirtualFree(self.gateway as _, 0, MEM_RELEASE).ok();
    }}

    /// Returns the pointer to the RWX gateway stub. A detour can cast this to the
    /// correct function signature and invoke the original syscall.
    pub fn gateway(&self) -> *const c_void {
        self.gateway as *const c_void
    }
}
