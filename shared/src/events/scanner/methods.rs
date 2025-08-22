#![cfg(feature = "user")]

use crate::events::scanner::FileScannerEvent;
use crate::traits::DbLoggable;
use log::error;
use rusqlite::{Connection, params};

impl DbLoggable for FileScannerEvent {
    fn send_to_db(&self, conn: &Connection) {
        conn.execute(
            "INSERT INTO file_scanner (file, rule_name) VALUES (?1, ?2)",
            params![&self.file, &self.rule_name],
        )
        .inspect_err(|e| {
            error!(
                "DB error inserting file_scanner (file={}, rule_name={}): {}",
                self.file, self.rule_name, e
            )
        })
        .ok();
    }
}
