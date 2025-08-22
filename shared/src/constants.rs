pub const USER_SHARED_SECTION_NAME: &str = "Global\\GladixSharedSection";
pub const KERNEL_SHARED_SECTION_NAME: &str = r"\BaseNamedObjects\Global\GladixSharedSection";
pub const SHARED_SECTION_SIZE: usize = 1024 * 1024; // 1 MiB

/// User-mode access path to the Gladix device driver
pub const DEVICE_SYMBOLIC_NAME: &str = r"\DosDevices\Gladix";
pub const ALT_DEVICE_SYMBOLIC_NAME: &str = r"\\.\Gladix";

/// Kernel-mode device name (mostly for internal/logging use)
pub const DEVICE_INTERNAL_NAME: &str = r"\Device\GladixDrv";



const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32     = 0;
const FILE_ANY_ACCESS: u32     = 0;

/// CTL_CODE(DeviceType, Function, Method, Access)
/// = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
macro_rules! ctl_code {
    ($dev:expr, $func:expr, $method:expr, $access:expr) => {
        ($dev << 16) | ($access << 14) | ($func << 2) | $method
    };
}

/// User-mode IOCTL to request a handle to the shared section.
/// Using METHOD_BUFFERED: output buffer returns a `HANDLE`.
///
/// Rationale in project:
/// The user agent should not depend on Global\ namespace rules. Brokering the handle from the
/// driver ensures the handle is created in the caller's process with the desired rights and
/// survives session/MIC quirks.
///
/// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
pub const IOCTL_GLADIX_GET_SECTION_HANDLE: u32 =
    ctl_code!(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// User-mode IOCTL to send a serialized Hook `Event` (prost-encoded) to the driver.
/// The input buffer is the encoded bytes; there is no output buffer.
///
/// The DLL hooks run in arbitrary processes. Sending events via IOCTL centralizes arbitration
/// in the driver and reuses the existing kernel-to-agent shared ring without making the DLL aware
/// of global object names.
///
/// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
pub const IOCTL_GLADIX_SEND_HOOK_EVENT: u32 =
    ctl_code!(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// User-mode IOCTL to initiate driver pre-unload sequence (quiesce + callback unregistration).
/// This prepares the driver for safe unloading by blocking new guarded entries, unregistering
/// all kernel callbacks (process, image-load, registry), and waiting for in-flight callbacks
/// to complete. The driver remains resident but can now be unloaded by the SCM.
///
/// This is intended to be called from the user-mode agent before `sc stop` is issued.
/// There is no input or output buffer.
///
/// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
pub const IOCTL_GLADIX_UNREGISTER_CALLBACKS: u32 =
    ctl_code!(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);

