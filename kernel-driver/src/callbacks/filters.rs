//! Compact, low‑overhead predicates that gate which events become telemetry. The goal is to keep
//! high‑signal data for threat hunting while trimming the most common system churn. All checks are
//! ASCII case‑insensitive without allocating, so these functions can be used freely on hot paths.
//!
//! Tuning notes
//! ------------
//! These filters intentionally bias toward reducing well‑known noise (WinSxS, DriverStore, system
//! boot processes) while keeping activity that malware commonly abuses (autoruns, services,
//! IFEO, Winlogon, AppInit, LSA, profile‑local loads). Adjust the allow/deny sets as you learn from
//! your environment. Prefer explicit prefixes to broad contains when possible.

/// ASCII lowercase for a single byte without allocating.
#[inline]
fn to_ascii_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) { b + 32 } else { b }
}

/// Case‑insensitive equality for two ASCII bytes.
#[inline]
fn eq_ci(a: u8, b: u8) -> bool {
    to_ascii_lower(a) == to_ascii_lower(b)
}

/// Return `true` if `haystack` starts with `prefix` (ASCII case‑insensitive) without allocating.
#[inline]
pub fn starts_with_ci(haystack: &str, prefix: &str) -> bool {
    let h = haystack.as_bytes();
    let p = prefix.as_bytes();
    if p.len() > h.len() {
        return false;
    }
    for i in 0..p.len() {
        if !eq_ci(h[i], p[i]) {
            return false;
        }
    }
    true
}

/// Return `true` if `haystack` contains `needle` (ASCII case‑insensitive) without allocating.
#[inline]
pub fn contains_ci(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let m = n.len();
    if m == 0 || m > h.len() {
        return false;
    }
    // Naive window scan is fine for short needles; avoids allocations on hot paths.
    for w in 0..=h.len() - m {
        let mut ok = true;
        for i in 0..m {
            if !eq_ci(h[w + i], n[i]) {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

/// Quick check for paths rooted under the Windows directory in either NT or DOS form.
///
/// Examples that return true:
///   `\SystemRoot\`
///   `C:\Windows\`
///   `\??\C:\Windows\`
///
/// This is intentionally simple and ASCII‑case‑insensitive.
#[inline]
fn is_windows_rooted(path: &str) -> bool {
    starts_with_ci(path, r"\systemroot\") ||
        contains_ci(path, r":\windows\")
}

/* =========================  IMAGE‑LOAD FILTERS  ========================= */

/// Decide whether to emit an image‑load event.
///
/// Heuristics:
/// - Drop loads in the System process (PID 4) and `smss.exe` to cut boot noise.
/// - Ignore very small images (< 4 KiB); usually stubs or artifacts.
/// - Ignore well‑known high‑churn system trees: WinSxS and DriverStore.
/// - Keep loads from user/profile locations and non‑Windows roots, which are high signal.
///
/// Parameters:
/// - `pid`: creator process id provided by the image‑load callback.
/// - `full_image_path`: NT or DOS style full path of the image.
/// - `image_size`: module size in bytes if available.
///
/// Returns:
/// - `true` if the event should be emitted; `false` to drop it.
///
/// TODO: add optional publisher trust (Microsoft‑signed suppression) when cert info is available.
#[inline]
pub fn should_emit_image_load(pid: u32, full_image_path: &str, image_size: u32) -> bool {
    // System PID and early session manager activity are extremely chatty at boot.
    if pid == 4 {
        return false;
    }
    if contains_ci(full_image_path, r"\system32\smss.exe") || contains_ci(full_image_path, r"\smss.exe") {
        return false;
    }

    // Guard against degenerate or placeholder images.
    if image_size < 4 * 1024 {
        return false;
    }

    // High‑churn system stores that rarely indicate compromise.
    if contains_ci(full_image_path, r"\winsxs\") {
        return false;
    }
    if contains_ci(full_image_path, r"\system32\driverstore\filerepository\") {
        return false;
    }

    // Retain by default. Even Windows‑rooted modules can matter (DLL search‑order abuse, side‑loading).
    true
}

/* =========================  REGISTRY FILTERS  ========================= */

/// Vendor configuration subtree we always want to keep, NT‑path form of `HKLM\Software\Gladix\`.
const VENDOR_KEY_PREFIX: &str = r"\REGISTRY\MACHINE\SOFTWARE\Gladix\";

/// Prefixes under HKLM/HKU/HKCU commonly abused for persistence or security control.
/// All are NT‑style to match what callbacks resolve via `ObQueryNameString`.
const SENSITIVE_PREFIXES: &[&str] = &[
    // Autoruns
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\REGISTRY\USER\", // per‑user hives; will further check for CurrentVersion\Run below via contains_ci
    // Services/drivers (Start/Type edits matter)
    r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\",
    // Image File Execution Options (debugger hijack, silent process exit)
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\",
    // AppInit_DLLs (legacy but still abused)
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\",
    // Winlogon shell/userinit/notify
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\",
    // LSA authentication packages/notification packages
    r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\",
    // Scheduled Tasks registration
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\",
];

/// Noisy hives we almost never care about for threat detection.
#[inline]
fn is_registry_noise_path(path_nt: &str) -> bool {
    contains_ci(path_nt, r"\classes\") ||
        contains_ci(path_nt, r"\muicache\") ||
        contains_ci(path_nt, r"\appcompatflags\") ||
        contains_ci(path_nt, r"\installer\products\")
}

/// Decide whether to emit a `RegNtPreSetValueKey` event.
///
/// Policy:
/// - Always keep writes under our vendor subtree.
/// - Keep writes under well‑known sensitive prefixes that influence persistence or auth.
/// - Drop known noisy areas like Classes, MuiCache and AppCompat when they fall through.
/// - For per‑user autoruns we also retain if the tail contains `\CurrentVersion\Run`.
///
/// Parameters:
/// - `key_path_nt`: NT‑style registry path, e.g., `\REGISTRY\MACHINE\SOFTWARE\...`.
/// - `_value_name`: optional value name; currently unused but reserved for future value‑level filters.
///
/// Returns:
/// - `true` if the event should be emitted; `false` to drop it.
///
/// TODO: add value‑specific rules (e.g., only `AppInit_DLLs`, `Debugger`, `Shell`) when needed.
#[inline]
pub fn should_emit_registry_setvalue(key_path_nt: &str, _value_name: Option<&str>) -> bool {
    // Always keep our own configuration changes.
    if starts_with_ci(key_path_nt, VENDOR_KEY_PREFIX) {
        return true;
    }

    // Commonly abused locations.
    if SENSITIVE_PREFIXES.iter().any(|p| starts_with_ci(key_path_nt, p)) {
        return true;
    }

    // Per‑user autoruns appear under user hives; keep if the tail looks like CurrentVersion\Run.
    if contains_ci(key_path_nt, r"\currentversion\run") || contains_ci(key_path_nt, r"\currentversion\runonce") {
        return true;
    }

    // Trim obvious noise.
    if is_registry_noise_path(key_path_nt) {
        return false;
    }

    // Default stance: retain. Registry is relatively low volume after earlier callback scoping.
    true
}

/* =========================  PROCESS FILTERS  ========================= */

/// Decide whether to emit a process‑creation event.
///
/// Heuristics:
/// - Drop very low PIDs which tend to be kernel/system services early in boot.
/// - Drop empty image paths.
/// - Keep everything else, including Windows‑rooted binaries, since command‑line or parent
///   relationships often carry investigative value even for system images.
///
/// Parameters:
/// - `pid`: process identifier.
/// - `image_path`: NT or DOS path of the image; may be empty for short windows.
///
/// Returns:
/// - `true` if the event should be emitted; `false` to drop it.
///
/// TODO: consider suppressing repeated service host churn if volume remains high in practice.
#[inline]
pub fn should_emit_process_create(pid: u32, image_path: &str) -> bool {
    if pid < 100 {
        return false;
    }
    if image_path.is_empty() {
        return false;
    }
    // Keep system‑rooted processes; even those can indicate abuse (e.g., LOLBins).
    let _ = is_windows_rooted(image_path); // Placeholder for future tuning.
    true
}
