// security.rs
//! Builds a SECURITY_DESCRIPTOR for the named SECTION so a standard Medium‑IL user process
//! can obtain a writable mapping to the shared ring, while letting us restrict who is allowed.
//!
//! Why this exists in the project:
//! - The user‑mode listener typically runs at Medium integrity; without a suitable label, MIC
//!   could block writes even if the DACL looks permissive.
//! - We tag the object with a Medium integrity label (SACL) and grant only the mapping rights
//!   needed by the consumer (DACL). This combination allows Medium‑IL processes to map the
//!   section for read/write, and also works for higher‑integrity callers such as Windows
//!   services that run as High or System.
//! - Keeping the policy here means we can later tighten the DACL (e.g., to a specific SID)
//!   without touching the ring or IOCTL code.
//!
//! Note: We open the section in the caller’s context (ZwOpenSection in the IOCTL path), so
//! both the DACL and the object’s integrity label apply to the caller’s token.

use core::{mem::size_of, ptr};
use wdk::println;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePoolWithTag, RtlAddAccessAllowedAce, RtlCreateAcl,
        RtlCreateSecurityDescriptor, RtlLengthSid, RtlSetDaclSecurityDescriptor,
    },
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, BOOLEAN, NTSTATUS, POOL_FLAG_PAGED, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_REVISION, SIZE_T, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS, SYSTEM_MANDATORY_LABEL_ACE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};

// Private imports that are not exposed by the crate bindings.
#[link(name = "ntoskrnl")]
unsafe extern "system" {
    fn RtlSetSaclSecurityDescriptor(
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        SaclPresent: BOOLEAN,
        Sacl: *mut ACL,
        SaclDefaulted: BOOLEAN,
    ) -> NTSTATUS;

    fn RtlAddMandatoryAce(
        Acl: *mut ACL,
        AceRevision: u32,
        AceFlags: u32,
        Sid: PSID,
        AceType: u8,
        AccessMask: u32,
    ) -> NTSTATUS;

    fn RtlValidSid(Sid: PSID) -> BOOLEAN;
}

const POOL_TAG: u32 = u32::from_le_bytes(*b"SDSC");

/// Mapping rights required by the user‑mode ring consumer.
/// Principle of least privilege: only map‑read and map‑write.
pub const SECTION_RW_MASK: u32 = wdk_sys::SECTION_MAP_READ | wdk_sys::SECTION_MAP_WRITE;

/// Minimal SD wrapper tying the descriptor buffer lifetime to this instance.
/// The allocation holds the SECURITY_DESCRIPTOR followed by DACL and SACL.
pub struct SecurityDescriptor {
    sd_ptr: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    /// Creates a SECURITY_DESCRIPTOR that:
    /// - DACL: grants `SECTION_MAP_READ | SECTION_MAP_WRITE` to Everyone.
    /// - SACL: applies a Medium integrity label with NO_WRITE_UP.
    ///
    /// This enables Medium‑IL processes to map the section for read/write, while higher‑IL
    /// services can also access it. The DACL can be tightened in the future to a specific
    /// SID or group without changing the rest of the driver.
    ///
    /// Safety
    /// - Must run at PASSIVE_LEVEL (paged allocation).
    /// - The returned pointer remains valid until this object is dropped.
    pub unsafe fn for_everyone() -> Result<SecurityDescriptor, NTSTATUS> {
        // Everyone SID: S-1-1-0
        static EVERYONE_SID: [u8; 12] = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let world: PSID = EVERYONE_SID.as_ptr() as PSID;

        // Medium IL SID: S-1-16-8192
        static MEDIUM_IL_SID: [u8; 12] = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00,
        ];
        let il_sid: PSID = MEDIUM_IL_SID.as_ptr() as PSID;

        if RtlValidSid(world) == 0 || RtlValidSid(il_sid) == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }

        // Single buffer: SD + DACL(+ACE+SID) + SACL(+ACE+SID).
        let sd_size = size_of::<SECURITY_DESCRIPTOR>();

        // DACL sizing (ACCESS_ALLOWED_ACE + SID).
        let world_len = RtlLengthSid(world) as usize;
        let dacl_ace_len = size_of::<ACCESS_ALLOWED_ACE>() + world_len - size_of::<u32>();
        let dacl_len = size_of::<ACL>() + dacl_ace_len;

        // SACL sizing (SYSTEM_MANDATORY_LABEL_ACE + SID).
        let il_len = RtlLengthSid(il_sid) as usize;
        let sacl_ace_len = size_of::<SYSTEM_MANDATORY_LABEL_ACE>() + il_len - size_of::<u32>();
        let sacl_len = size_of::<ACL>() + sacl_ace_len;

        let total = sd_size + dacl_len + sacl_len;

        let raw = ExAllocatePool2(POOL_FLAG_PAGED, total as SIZE_T, POOL_TAG);
        if raw.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        ptr::write_bytes(raw as *mut u8, 0, total);

        let sd_ptr = raw as PSECURITY_DESCRIPTOR;
        let dacl_ptr = (raw as *mut u8).add(sd_size) as *mut ACL;
        let sacl_ptr = (raw as *mut u8).add(sd_size + dacl_len) as *mut ACL;

        // Base SD.
        let st_sd = RtlCreateSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION as u32);
        if st_sd != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_sd);
        }

        // DACL: Everyone -> map read/write.
        let st_dacl = RtlCreateAcl(dacl_ptr, dacl_len as u32, ACL_REVISION as u32);
        if st_dacl != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_dacl);
        }
        let st_allow = RtlAddAccessAllowedAce(dacl_ptr, ACL_REVISION as u32, SECTION_RW_MASK, world);
        if st_allow != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_allow);
        }
        let st_set_dacl = RtlSetDaclSecurityDescriptor(sd_ptr, 1 as BOOLEAN, dacl_ptr, 0 as BOOLEAN);
        if st_set_dacl != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_set_dacl);
        }

        // SACL: Medium IL + NO_WRITE_UP so Medium‑IL callers can write; lower IL cannot write up.
        let st_sacl = RtlCreateAcl(sacl_ptr, sacl_len as u32, ACL_REVISION as u32);
        if st_sacl != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_sacl);
        }
        // AceType 0x11 = SYSTEM_MANDATORY_LABEL_ACE_TYPE.
        let st_mace = RtlAddMandatoryAce(
            sacl_ptr,
            ACL_REVISION as u32,
            0,
            il_sid,
            0x11,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP as u32,
        );
        if st_mace != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_mace);
        }
        let st_set_sacl = RtlSetSaclSecurityDescriptor(sd_ptr, 1 as BOOLEAN, sacl_ptr, 0 as BOOLEAN);
        if st_set_sacl != STATUS_SUCCESS {
            ExFreePoolWithTag(raw, POOL_TAG);
            return Err(st_set_sacl);
        }

        println!("[Security] SD ready at {:p}", sd_ptr);
        Ok(SecurityDescriptor { sd_ptr })
    }

    /// Raw SECURITY_DESCRIPTOR pointer (valid until `Drop`).
    #[inline]
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.sd_ptr
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !self.sd_ptr.is_null() {
                ExFreePoolWithTag(self.sd_ptr.cast(), POOL_TAG);
                self.sd_ptr = ptr::null_mut();
            }
        }
    }
}
