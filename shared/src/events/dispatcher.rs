#![cfg(feature = "user")]

use crate::events::{Event, EventKind};
use crate::traits::DbLoggable;
use rusqlite::Connection;

impl DbLoggable for Event {
    fn send_to_db(&self, conn: &Connection) {
        match &self.kind {
            Some(EventKind::Hook(h))            => h.send_to_db(conn),
            Some(EventKind::Scanner(s))    => s.send_to_db(conn),
            Some(EventKind::ProcessEvent(pe)) => pe.send_to_db(conn),
            Some(EventKind::ImageLoad(il))  => il.send_to_db(conn),
            Some(EventKind::Registry(re))     => re.send_to_db(conn),
            None => log::warn!("[Event] Event has empty kind; dropping."),
        }
    }
}