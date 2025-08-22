#![cfg(feature = "user")]

use rusqlite::Connection;

pub trait DbLoggable {
    fn send_to_db(&self, conn: &Connection);
}
