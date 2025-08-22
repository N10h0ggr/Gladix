use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, thread, time::Duration};

use crate::config::{ConfigManager, DirectoryRisk};
use crate::scanner::cache::ScanCache;
use crate::EventTx;
use log::{debug, error, info};
use shared::errors::ScannerError;
use shared::events::scanner::FileScannerEvent;
use shared::events::{Event, EventKind};
use yara_x::{Rules, Scanner};

/// Worker responsible for scanning files for a specific risk group.
pub struct Worker {
    rules: Arc<Rules>,
    config: Arc<ConfigManager>,
    risk: DirectoryRisk,
}

impl Worker {
    /// Creates a new `Worker`.
    pub fn new(rules: Arc<Rules>, config: Arc<ConfigManager>, risk: DirectoryRisk) -> Self {
        Self {
            rules,
            config,
            risk,
        }
    }

    /// Runs the worker loop, scanning directories and sleeping based on the current configuration.
    pub fn run(&self, cache: &mut ScanCache, evt_tx: EventTx) {
        let mut interval = self.current_interval().unwrap_or(600);

        loop {
            self.scan_directories(cache, evt_tx.clone());

            // Re-read interval in case it changed
            if let Some(new_int) = self.current_interval() {
                if new_int != interval {
                    info!(
                        "Risk {:?} interval changed from {}s to {}s",
                        self.risk, interval, new_int
                    );
                    interval = new_int;
                }
            }

            debug!("Worker for {:?} sleeping {}s", self.risk, interval);
            thread::sleep(Duration::from_secs(interval));
        }
    }

    /// Retrieves the current scheduled interval for this worker's risk group.
    fn current_interval(&self) -> Option<u64> {
        self.config
            .get()
            .scanner
            .risk_groups
            .get(&self.risk)
            .and_then(|g| g.scheduled_interval)
    }

    /// Scans all configured directories for this risk group.
    fn scan_directories(&self, cache: &mut ScanCache, event_tx: EventTx) {
        let config = self.config.get();
        let dirs = match config.scanner.risk_groups.get(&self.risk) {
            Some(cfg) => &cfg.directories,
            None => {
                debug!("No directories configured for risk {:?}", self.risk);
                return;
            }
        };

        let mut scanner = Scanner::new(&self.rules);
        
        // TODO: Rise warning or error if directory does not exist
        for path in list_files(dirs) {
            match scan_one(&mut scanner, &path, cache) {
                Ok(events) if !events.is_empty() => {
                    for fs_evt in events {
                        let evt = Event{kind: Option::from(EventKind::Scanner(fs_evt)) };
                        if let Err(e) = event_tx.send(evt) {
                            error!("event channel closed: {e}. Skipping event.");
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => error!("Scan {} failed: {}", path.display(), e),
            }
        }
    }
}

/// Spawns a detached worker thread for a specific risk group.
pub fn spawn_worker(
    rules: Arc<Rules>,
    config: Arc<ConfigManager>,
    risk: DirectoryRisk,
    mut cache: ScanCache,
    evt_tx: EventTx,
) {
    let thread_handle = thread::Builder::new().name("scanner_worker".into());
    // TODO: Handle error
    let _ = thread_handle.spawn(move || Worker::new(rules, config, risk).run(&mut cache, evt_tx));
}

/// Scans a single file if it has changed since the last scan.
fn scan_one(
    scanner: &mut Scanner,
    path: &Path,
    cache: &mut ScanCache,
) -> Result<Vec<FileScannerEvent>, ScannerError> {
    let mut events = Vec::new();

    let metadata = fs::metadata(path).map_err(|source| ScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if cache.is_unchanged(path, &metadata) {
        return Ok(events);
    }

    let buf = fs::read(path).map_err(|source| ScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let matches = scanner.scan(&buf).map_err(|source| ScannerError::Scan {
        path: path.to_path_buf(),
        source,
    })?;

    for m in matches.matching_rules() {
        let event = FileScannerEvent {
            file: path.to_string_lossy().into_owned(),
            rule_name: m.identifier().to_string(),
        };
        info!("{} => {}", event.file, event.rule_name);
        events.push(event);
    }

    cache.update(path, &metadata);
    Ok(events)
}

/// Returns a list of regular files directly inside the given directories (non-recursive).
/// Warning: Vec uses memory and this may be a problem for large directories
pub fn list_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter()
        .filter_map(|dir| fs::read_dir(dir).ok())
        .flat_map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect()
}
