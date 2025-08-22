// src/db/connection.rs
//! Opening and initialising SQLite with runtime parameters.

use crate::config::{DatabaseConfig, SynchronousMode};
use rusqlite::Connection;
use std::path::PathBuf;
use std::{path::Path, time::Duration};

/// Allow converting your enum into exactly the strings SQLite expects
impl SynchronousMode {
    pub fn as_str(&self) -> &str {
        match self {
            SynchronousMode::Off => "OFF",
            SynchronousMode::Normal => "NORMAL",
            SynchronousMode::Full => "FULL",
            SynchronousMode::Extra => "EXTRA",
        }
    }
}

/// Open a single connection and apply pragmas
fn open_db_connection(path: &Path, cfg: &DatabaseConfig) -> Result<Connection, rusqlite::Error> {
    // Creates the file if it does not exist
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(1_000))?;
    conn.pragma_update(None, "journal_mode", &"WAL")?;
    conn.pragma_update(None, "synchronous", &cfg.synchronous.as_str())?;
    Ok(conn)
}

/// Public: open-or-create the DB at `exe_dir.join(cfg.path)`, apply pragmas,
/// purge on restart, and run `schema.sql` on first run
pub fn init_database(
    db_path: &PathBuf,
    cfg: &DatabaseConfig,
) -> Result<Connection, rusqlite::Error> {
    let path = db_path.join(&cfg.path);
    let first_run = !path.exists();

    let conn = open_db_connection(&path, cfg)?;
    conn.pragma_update(None, "journal_size_limit", &(cfg.journal_size_limit as i64))?;

    if first_run {
        let schema = include_str!("schema.sql");
        conn.execute_batch(schema)?;
    }

    Ok(conn)
}
