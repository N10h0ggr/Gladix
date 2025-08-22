#![cfg(feature = "user")]

//! Database insertion for kernel callback events (process, image-load, registry).
//!
//! Each event type has a dedicated insert function containing the SQL and field mapping. Public
//! prost-generated messages implement `DbLoggable` and delegate to those helpers. This keeps the
//! hot path small and makes schema migrations easier to test in isolation.

use crate::traits::DbLoggable;
use log::error;
use rusqlite::{params, Connection};

// Prost-generated types for callback events.
use crate::events::callbacks::{ImageLoadEvent, ProcessEvent, RegistryEvent};

/// Inserts a `process_event` row.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `evt`: concrete ProcessEvent payload.
///
/// Precautions:
/// - `image_path` and `cmdline` are user/OS provided; avoid logging full values on error to reduce
///   noise and accidental leakage in logs. Keep identifiers like pid for troubleshooting.
pub fn insert_process_event(conn: &Connection, evt: &ProcessEvent) {
    conn.execute(
        "INSERT INTO process_event (pid, ppid, image_path, cmdline) VALUES (?1, ?2, ?3, ?4)",
        params![evt.pid as i64, evt.ppid as i64, &evt.image_path, &evt.cmdline],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting process_event (pid={}, ppid={}): {}",
            evt.pid, evt.ppid, e
        )
        })
        .ok();
}

/// Inserts an `image_load_event` row.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `evt`: concrete ImageLoadEvent payload.
///
/// Precautions:
/// - `image_base` is stored as INTEGER (64-bit); it may be zero on failures and should still be
///   stored as-is for triage.
pub fn insert_image_load_event(conn: &Connection, evt: &ImageLoadEvent) {
    conn.execute(
        "INSERT INTO image_load_event (image_base, image_size, full_image_name, process_id) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            evt.image_base as i64,
            evt.image_size as i64,
            &evt.full_image_name,
            evt.process_id as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting image_load_event (proc_id={}, base=0x{:x}): {}",
            evt.process_id, evt.image_base, e
        )
        })
        .ok();
}

/// Inserts a `registry_event` row.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `evt`: concrete RegistryEvent payload.
///
/// Precautions:
/// - `old_value` / `new_value` may be large; they are stored as BLOB. Calls avoid printing blob
///   contents in logs. Empty vectors are accepted and mean “not applicable”.
pub fn insert_registry_event(conn: &Connection, evt: &RegistryEvent) {
    conn.execute(
        "INSERT INTO registry_event (op_type, key_path, old_value, new_value, process_id) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            evt.op_type as i64,
            &evt.key_path,
            &evt.old_value,
            &evt.new_value,
            evt.process_id as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting registry_event (proc_id={}, key={}): {}",
            evt.process_id, &evt.key_path, e
        )
        })
        .ok();
}

// ────────────────────────────────────────────────────
// DbLoggable implementations
// ────────────────────────────────────────────────────

impl DbLoggable for ProcessEvent {
    /// Persists a ProcessEvent into the `process_event` table.
    ///
    /// Parameters:
    /// - `conn`: opened SQLite connection.
    ///
    /// Returns:
    /// - Nothing. Errors are logged and swallowed to keep the pipeline resilient under load.
    ///
    /// Precautions:
    /// - Ensure `PRAGMA foreign_keys` and WAL settings are applied by the caller if required.
    fn send_to_db(&self, conn: &Connection) {
        insert_process_event(conn, self);
    }
}

impl DbLoggable for ImageLoadEvent {
    /// Persists an ImageLoadEvent into the `image_load_event` table.
    ///
    /// Parameters:
    /// - `conn`: opened SQLite connection.
    fn send_to_db(&self, conn: &Connection) {
        insert_image_load_event(conn, self);
    }
}

impl DbLoggable for RegistryEvent {
    /// Persists a RegistryEvent into the `registry_event` table.
    ///
    /// Parameters:
    /// - `conn`: opened SQLite connection.
    fn send_to_db(&self, conn: &Connection) {
        insert_registry_event(conn, self);
    }
}
