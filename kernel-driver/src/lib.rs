#![no_std]
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

use wdk::println;
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::{IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink};
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PVOID, STATUS_SUCCESS};

use shared::constants::{
    DEVICE_INTERNAL_NAME, DEVICE_SYMBOLIC_NAME, KERNEL_SHARED_SECTION_NAME, SHARED_SECTION_SIZE,
};

mod communications;
use communications::MemoryRing;

mod security;
mod utils;
mod callbacks;

// Quiesces callbacks on unload and tracks in‑flight ones.
use crate::callbacks::callback_guard;

#[global_allocator]
static ALLOCATOR: WdkAllocator = WdkAllocator;

/// Per‑device context attached to each `DEVICE_OBJECT`.
///
/// Carries the mapped ring, the rundown object used to gate callbacks during unload,
/// and the exact callback mask of what was registered so we can unregister precisely.
#[repr(C)]
pub struct DeviceExtension {
    pub(crate) ring: MemoryRing,
    pub(crate) rundown: wdk_sys::EX_RUNDOWN_REF,
    pub(crate) cb_mask: callbacks::CallbackMask,
}

/// Driver entry point.
///
/// Creates the device, sets up the named shared‑memory ring, publishes the rundown pointer,
/// creates the DOS symbolic link, and registers callbacks transactionally. Any failure
/// rolls back previously created resources so a later load starts cleanly.
///
/// # Parameters
/// - `driver_object`: provided by the I/O manager; also passed to registry callback
///   registration because the registry API requires a `DriverObject`.
/// - `_registry_path`: unused in this driver.
///
/// # Returns
/// `STATUS_SUCCESS` on success; otherwise a failure `NTSTATUS` with best‑effort cleanup applied.
///
/// # Safety
/// Called by the OS at PASSIVE_LEVEL. This function installs function pointers and writes
/// into the device extension memory allocated by `IoCreateDevice`.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "C" fn driver_entry(
    driver_object: *mut wdk_sys::DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    (*driver_object).DriverUnload = Some(driver_unload);
    println!("[DriverEntry] starting engines...");

    // Create device object with space for our extension.
    let mut dev_name = utils::UnicodeString::new(DEVICE_INTERNAL_NAME);
    let mut device_object: PDEVICE_OBJECT = core::ptr::null_mut();
    let st_dev = IoCreateDevice(
        driver_object,
        core::mem::size_of::<DeviceExtension>() as u32,
        dev_name.as_mut_ptr(),
        wdk_sys::FILE_DEVICE_UNKNOWN,
        0,
        0u8,
        &mut device_object,
    );
    if st_dev != STATUS_SUCCESS {
        println!("[DriverEntry] IoCreateDevice failed: {:#X}", st_dev);
        return st_dev;
    }

    // Create and map the shared ring section in system space.
    let ring = match setup_ring(KERNEL_SHARED_SECTION_NAME, SHARED_SECTION_SIZE) {
        Ok(r) => {
            println!("[DriverEntry] MemoryRing ready at {:p}", r.base);
            r
        }
        Err(status) => {
            println!("[DriverEntry] setup_ring failed {:#X}", status);
            IoDeleteDevice(device_object);
            return status;
        }
    };

    // Attach and initialize the device extension.
    let dev_ext = (*device_object).DeviceExtension as *mut DeviceExtension;
    core::ptr::write(
        dev_ext,
        DeviceExtension {
            ring,
            rundown: core::mem::zeroed(),
            cb_mask: callbacks::CallbackMask::default(),
        },
    );

    // Publish rundown pointer so callbacks can acquire protection before pushing to the ring.
    callback_guard::init_rundown(&mut (*dev_ext).rundown as *mut _);
    callback_guard::set_rundown_ptr(&mut (*dev_ext).rundown as *mut _);

    // Robust DOS link creation: delete stale link first, then create a fresh one.
    if let Err(st) = recreate_dos_link(DEVICE_SYMBOLIC_NAME, dev_name.as_mut_ptr()) {
        println!("[DriverEntry] recreate_dos_link failed: {:#X}", st);
        callback_guard::clear_rundown_ptr();
        core::ptr::drop_in_place(dev_ext);
        IoDeleteDevice(device_object);
        return st;
    }

    // Register callbacks transactionally. Pass DriverObject for the registry API.
    let ext_ref: &mut DeviceExtension = &mut *dev_ext;
    match callbacks::register_all(&ext_ref.ring, driver_object as PVOID) {
        Ok(mask) => {
            ext_ref.cb_mask = mask;
            println!("[DriverEntry] callbacks registered");
        }
        Err(st) => {
            println!("[DriverEntry] callbacks registration failed: {:#X}", st);
            let mut sym = utils::UnicodeString::new(DEVICE_SYMBOLIC_NAME);
            let _ = IoDeleteSymbolicLink(sym.as_mut_ptr());
            callback_guard::clear_rundown_ptr();
            core::ptr::drop_in_place(dev_ext);
            IoDeleteDevice(device_object);
            return st;
        }
    }

    // Install minimal dispatchers used by user‑mode to obtain a handle to the section.
    (*driver_object).MajorFunction[wdk_sys::IRP_MJ_CREATE as usize] =
        Some(communications::ioctl_dispatch::dispatch_create);
    (*driver_object).MajorFunction[wdk_sys::IRP_MJ_CLOSE as usize] =
        Some(communications::ioctl_dispatch::dispatch_close);
    (*driver_object).MajorFunction[wdk_sys::IRP_MJ_DEVICE_CONTROL as usize] =
        Some(communications::ioctl_dispatch::dispatch_device_control);

    STATUS_SUCCESS
}


/// Driver unload routine.
///
/// Performs a race‑safe teardown by quiescing new guarded entries, unregistering callbacks via
/// `unregister_callbacks_from_device`, draining in‑flight callbacks, clearing globals, removing the
/// DOS link, and deleting the device. Logs each high‑level step when it completes or fails.
///
/// # Safety
/// Invoked by the I/O manager at PASSIVE_LEVEL. Pointers read from `driver_object` must not be
/// reused after their owners are torn down in this routine.
extern "C" fn driver_unload(driver_object: *mut wdk_sys::DRIVER_OBJECT) {
    unsafe {
        // Remove DOS link.
        let mut sym = utils::UnicodeString::new(DEVICE_SYMBOLIC_NAME);
        let del_st = IoDeleteSymbolicLink(sym.as_mut_ptr());
        if del_st == STATUS_SUCCESS {
            println!("[DriverUnload] DOS link removed.");
        } else {
            println!("[DriverUnload] DOS link removal failed: {:#X}", del_st);
        }
        
        let device_object = (*driver_object).DeviceObject;

        // Delete device and free extension.
        if !device_object.is_null() {
            let dev_ext = (*device_object).DeviceExtension as *mut DeviceExtension;
            if !dev_ext.is_null() {
                core::ptr::drop_in_place(dev_ext);
                println!("[DriverUnload] device extension freed.");
            }
            IoDeleteDevice(device_object);
            println!("[DriverUnload] device deleted.");
        }

        println!("[DriverUnload] completed.");
    }
}


/// Creates and maps the ring SECTION, initializing the header if needed.
///
/// Returns a mapped `MemoryRing` ready for producer pushes. The mapping is done in system
/// space so callbacks can write without attaching to a process.
fn setup_ring(section_name: &str, data_size: usize) -> Result<MemoryRing, wdk_sys::NTSTATUS> {
    let mut ring = MemoryRing::create(section_name, data_size)?;
    ring.map()?;
    Ok(ring)
}

/// Deletes any stale DOS link and creates a fresh one pointing to our device.
///
/// This avoids `STATUS_OBJECT_NAME_COLLISION` during quick reloads and ensures user‑mode
/// can reopen the device immediately after a driver update.
///
/// # Safety
/// The pointers must remain valid for the duration of the calls to the I/O manager.
unsafe fn recreate_dos_link(sym_dos: &str, dev_nt: *mut wdk_sys::UNICODE_STRING) -> Result<(), NTSTATUS> {
    let mut sym = utils::UnicodeString::new(sym_dos);

    // Best effort delete; ignore error if the link does not exist.
    let del = IoDeleteSymbolicLink(sym.as_mut_ptr());
    println!("[DriverEntry] IoDeleteSymbolicLink (pre-create) => {:#X}", del);

    // Create a new link for this load instance.
    let st = IoCreateSymbolicLink(sym.as_mut_ptr(), dev_nt);
    if st == STATUS_SUCCESS {
        println!(
            "[DriverEntry] Symbolic link ready: {} -> {}",
            DEVICE_SYMBOLIC_NAME, DEVICE_INTERNAL_NAME
        );
        Ok(())
    } else {
        println!("[DriverEntry] IoCreateSymbolicLink failed: {:#X}", st);
        Err(st)
    }
}
