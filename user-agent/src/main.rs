#![allow(dead_code)]
use crate::cleanup::ConsoleCleanup;
use crate::communications::ioctl::send_unregister_callbacks_ioctl;
use crate::communications::MemoryRing;
use crate::config::ConfigManager;
use crate::db::connection::init_database;
use crate::scanner::service::ScannerService;
use crate::scanner::signatures::{SignatureSource, Signatures};
use log::{error, info, warn};
use prost::Message;
use shared::constants::USER_SHARED_SECTION_NAME;
use shared::events::Event;
use shared::traits::DbLoggable;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;
use std::{env, panic, thread};

mod communications;
mod config;
mod db;
mod logger;
mod scanner;
mod cleanup;

// TODO: move these channel aliases next to the DB/event plumbing (e.g., db/mod.rs or events/mod.rs).
pub type EventTx = Sender<Event>;
pub type EventRx = Receiver<Event>;

/// Entry point for the user-mode agent.
/// Initializes logging and configuration, starts the DB pipeline, launches the file
/// scanner service, and finally spawns the ring listener that ingests kernel events.
///
/// The main thread parks indefinitely; a future control plane can unpark/shutdown.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Keep logger alive for the duration of the process.
    let _logger = logger::init_logger()?;
    let _cleanup = ConsoleCleanup::new(|| { send_unregister_callbacks_ioctl(); });

    // Resolve the directory that hosts config and the DB.
    let mut current_directory = env::current_exe()?;
    current_directory.pop();

    let config_path = find_config_file();
    let cfg_mgr = Arc::new(ConfigManager::new(&config_path)?);
    info!("Configuration file loaded successfully");

    // Start DB pipeline.
    let (db_tx, db_rx): (EventTx, EventRx) = std::sync::mpsc::channel();
    let db_conn = init_database(&current_directory, &cfg_mgr.get().database)?;
    spawn_db_listener(db_conn, db_rx);
    info!("Database created and listening for events");

    // Launch file scanner in the background.
    init_scanner(cfg_mgr.clone(), db_tx.clone());
    info!("File scanner started");

    // Begin ingesting events from the kernel ring.
    spawn_ring_listener(db_tx);

    // The agent stays resident; add a control plane or signal handling when needed.
    thread::park();
    // Unreachable under normal operation.
    // Returning Ok keeps signature compatibility for integration tests.
    #[allow(unreachable_code)]
    Ok(())
}


/// Spawn a background thread that reads frames from the shared ring and forwards
/// decoded `Event`s to the DB thread.
///
/// Backpressure strategy is simple polling with a coarse sleep. A future revision
/// should replace this with an event-based wait coming from the kernel (e.g. an
/// IOCTL that blocks until a frame is published).
fn spawn_ring_listener(db_tx: Sender<Event>) {
    let builder = thread::Builder::new().name("ring_listener".into());
    match builder.spawn(move || {
        let mut ring = match MemoryRing::open(USER_SHARED_SECTION_NAME) {
            Ok(r) => r,
            Err(e) => {
                // Panic here terminates only the listener thread. This is a hard-fail condition
                // since we cannot consume kernel events without the ring mapping.
                panic!("Failed to open MemoryRing: {e}");
            }
        };

        loop {
            if let Some(frame) = ring.read_next() {
                match Event::decode(&*frame) {
                    Ok(ev) => {
                        if let Err(err) = db_tx.send(ev) {
                            error!("Failed to send event to DB thread: {err}");
                        }
                    }
                    Err(e) => {
                        warn!("Tried to decode a malformed event: {e}");
                    }
                }
            } else {
                // TODO: replace with kernel->UM signaling. Options:
                //  - Blocking IOCTL that completes when producer publishes new bytes.
                //  - Named event shared via SECTION + KeSetEvent/NtCreateEvent.
                thread::park_timeout(Duration::from_millis(500));
            }
        }
    }) {
        Ok(_handle) => {
            // No noisy log here; the DB and scanner logs above are enough for one-time milestones.
        }
        Err(e) => {
            // This is recoverable only if the caller installs a different ingestion path.
            error!("Failed to spawn ring listener thread: {e}");
        }
    }
}

/// Spawn the DB listener thread that receives events and persists them.
/// Unknown or not-yet-implemented event kinds are logged and dropped.
///
/// If the channel closes unexpectedly, the thread panics to surface a logic error.
fn spawn_db_listener(db_conn: rusqlite::Connection, db_rx: EventRx) {
    let builder = thread::Builder::new().name("event_listener".into());
    if let Err(e) = builder.spawn(move || {
        for ev in db_rx.iter() {
            ev.send_to_db(&db_conn);
        }
        panic!("All event channel senders dropped!");
    }) {
        error!("Failed to spawn DB listener thread: {e}");
    }
}

/// Start the file scanner in a dedicated thread. The signature loader can fail or panic;
/// both paths are caught and logged so the rest of the agent remains healthy.
fn init_scanner(cfg_mgr: Arc<ConfigManager>, evt_tx: EventTx) {
    let rule_path = cfg_mgr.get().scanner.rule_path.clone();
    let builder = thread::Builder::new().name("scanner".into());

    if let Err(e) = builder.spawn(move || {
        // Catch panics so we can log them instead of taking down the process.
        let load_result =
            panic::catch_unwind(|| Signatures::load(SignatureSource::File(rule_path)));

        match load_result {
            Ok(Ok(signatures)) => {
                let count = signatures.iter().count();
                info!("Loaded {} rules", count);
                ScannerService::new(cfg_mgr, Arc::new(signatures), evt_tx).start();
                info!("Scanners launched");
            }
            Ok(Err(e)) => {
                error!("Failed to load signatures: {e}. Skipping scanner module");
            }
            Err(panic_info) => {
                error!("Signature loader panicked: {:?}. Skipping scanner module", panic_info);
            }
        }
    }) {
        error!("Failed to spawn scanner thread: {e}");
    }
}

/// Find the `config.toml` path by checking an override environment variable first
/// and falling back to a file next to the running executable.
///
/// This function never panics; it returns a path even if the file is missing so
/// the caller can surface a clean configuration error.
fn find_config_file() -> PathBuf {
    if let Some(cfg) = env::var_os("GLADIX_CONFIG") {
        return PathBuf::from(cfg);
    }

    let mut exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe_path.pop();
    exe_path.push("config.toml");
    exe_path
}
