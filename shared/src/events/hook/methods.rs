#![cfg(feature = "user")]

//! Database insertion for hook events with per-variant handlers.
//!
//! Each match arm delegates to a specialized function that knows how to persist its payload.
//! This keeps the dispatcher small and the SQL isolated, which makes testing and migrations
//! easier without touching the event routing logic.

use crate::traits::DbLoggable;
use log::{error, warn};
use rusqlite::{params, Connection};

use crate::events::hook::{
    self, HookEvent,
    NtCreateThreadExEvent, NtMapViewOfSectionEvent, NtProtectVirtualMemoryEvent, NtSetValueKeyEvent,
};

impl HookEvent {
    /// Inserts the parent row into `hook_event` and returns the new rowid.
    ///
    /// Parameters:
    /// - `conn`: opened SQLite connection.
    /// - `hook_type`: discriminator string for readability and filtering.
    ///
    /// Returns:
    /// - Rowid of the inserted parent row.
    ///
    /// Precautions:
    /// - Requires the `status` column to exist in `hook_event`. If not available, switch to
    ///   `insert_parent_legacy`.
    fn insert_parent(&self, conn: &Connection, hook_type: &str) -> i64 {
        conn.execute(
            "INSERT INTO hook_event (pid, tid, payload_kind, status) VALUES (?1, ?2, ?3, ?4)",
            params![self.pid, self.tid, hook_type, self.status],
        )
            .inspect_err(|e| {
                error!(
                "DB error inserting hook_event (pid={}, tid={}, kind={}): {}",
                self.pid, self.tid, hook_type, e
            )
            })
            .ok();
        conn.last_insert_rowid()
    }
}

impl DbLoggable for HookEvent {
    /// Inserts the HookEvent into the database using per-variant handlers.
    ///
    /// Parameters:
    /// - `conn`: opened SQLite connection.
    ///
    /// Behavior:
    /// - Dispatches on the oneof discriminator and calls a dedicated insert function for the
    ///   concrete payload. The parent row is created once and the child row references it.
    fn send_to_db(&self, conn: &Connection) {
        let Some(hp) = &self.payload else {
            error!("Missing payload for HookEvent: pid={}, tid={}", self.pid, self.tid);
            return;
        };

        let Some(kind) = &hp.payload else {
            warn!("Empty HookPayload oneof for HookEvent(pid={}, tid={})", self.pid, self.tid);
            return;
        };

        match kind {
            hook::hook_payload::Payload::NtCreateThreadEx(evt) => {
                let id = self.insert_parent(conn, "NtCreateThreadEx");
                insert_nt_create_thread_ex(conn, id, evt);
            }
            hook::hook_payload::Payload::NtMapViewOfSection(evt) => {
                let id = self.insert_parent(conn, "NtMapViewOfSection");
                insert_nt_map_view_of_section(conn, id, evt);
            }
            hook::hook_payload::Payload::NtProtectVirtualMemory(evt) => {
                let id = self.insert_parent(conn, "NtProtectVirtualMemory");
                insert_nt_protect_virtual_memory(conn, id, evt);
            }
            hook::hook_payload::Payload::NtSetValueKey(evt) => {
                let id = self.insert_parent(conn, "NtSetValueKey");
                insert_nt_set_value_key(conn, id, evt);
            }
        }
    }
}

// ────────────────────────────────────────────────────
// Per-variant insertion helpers
// ────────────────────────────────────────────────────

/// Inserts the child row for NtCreateThreadEx.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `event_id`: parent rowid in `hook_event`.
/// - `evt`: concrete payload.
///
/// Precautions:
/// - All integer fields are stored as INTEGER; use i64 conversions to avoid panics on 32→64 casts.
fn insert_nt_create_thread_ex(conn: &Connection, event_id: i64, evt: &NtCreateThreadExEvent) {
    conn.execute(
        "INSERT INTO hook_event_nt_create_thread_ex \
            (event_id, start_routine, start_argument, create_flags, process_handle, desired_access) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event_id,
            evt.start_routine as i64,
            evt.start_argument as i64,
            evt.create_flags as i64,
            evt.process_handle as i64,
            evt.desired_access as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting hook_event_nt_create_thread_ex (event_id={}): {}",
            event_id, e
        )
        })
        .ok();
}

/// Inserts the child row for NtMapViewOfSection.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `event_id`: parent rowid in `hook_event`.
/// - `evt`: concrete payload.
///
/// Precautions:
/// - `base_address` and `view_size` can be zero on failure; keep them as-is for triage.
fn insert_nt_map_view_of_section(conn: &Connection, event_id: i64, evt: &NtMapViewOfSectionEvent) {
    conn.execute(
        "INSERT INTO hook_event_nt_map_view_of_section \
            (event_id, base_address, view_size, win32_protect, allocation_type, process_handle) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event_id,
            evt.base_address as i64,
            evt.view_size as i64,
            evt.win32_protect as i64,
            evt.allocation_type as i64,
            evt.process_handle as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting hook_event_nt_map_view_of_section (event_id={}): {}",
            event_id, e
        )
        })
        .ok();
}

/// Inserts the child row for NtProtectVirtualMemory.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `event_id`: parent rowid in `hook_event`.
/// - `evt`: concrete payload.
///
/// Precautions:
/// - `old_protect` may be zero if the original API failed; still useful for correlation.
fn insert_nt_protect_virtual_memory(conn: &Connection, event_id: i64, evt: &NtProtectVirtualMemoryEvent) {
    conn.execute(
        "INSERT INTO hook_event_nt_protect_virtual_memory \
            (event_id, base_address, region_size, new_protect, old_protect) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event_id,
            evt.base_address as i64,
            evt.region_size as i64,
            evt.new_protect as i64,
            evt.old_protect as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting hook_event_nt_protect_virtual_memory (event_id={}): {}",
            event_id, e
        )
        })
        .ok();
}

/// Inserts the child row for NtSetValueKey.
///
/// Parameters:
/// - `conn`: opened SQLite connection.
/// - `event_id`: parent rowid in `hook_event`.
/// - `evt`: concrete payload.
///
/// Precautions:
/// - `key_path` resolution is best-effort; empty strings are accepted to avoid blocking inserts.
fn insert_nt_set_value_key(conn: &Connection, event_id: i64, evt: &NtSetValueKeyEvent) {
    conn.execute(
        "INSERT INTO hook_event_nt_set_value_key \
            (event_id, key_path, value_name, value_type, data_size) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event_id,
            &evt.key_path,
            &evt.value_name,
            evt.value_type as i64,
            evt.data_size as i64
        ],
    )
        .inspect_err(|e| {
            error!(
            "DB error inserting hook_event_nt_set_value_key (event_id={}): {}",
            event_id, e
        )
        })
        .ok();
}
