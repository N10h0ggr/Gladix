use crate::config::ConfigManager;
use crate::scanner::cache::ScanCache;
use crate::scanner::worker::spawn_worker;
use crate::EventTx;
use std::sync::Arc;
use yara_x::Rules;

/// Service that launches and manages scanning workers for each risk group.
pub struct ScannerService {
    cfg_mgr: Arc<ConfigManager>,
    rules: Arc<Rules>,
    evt_tx: EventTx,
}

impl ScannerService {
    /// Create a new ScannerService given a shared ConfigManager and compiled rules.
    pub fn new(cfg_mgr: Arc<ConfigManager>, rules: Arc<Rules>, evt_tx: EventTx) -> Self {
        ScannerService {
            cfg_mgr,
            rules,
            evt_tx,
        }
    }

    /// Spawn a worker thread for each configured risk group.
    /// Each worker will periodically scan directories and pick up any interval changes on the fly.
    pub fn start(self) {
        let risk_groups = &self.cfg_mgr.get().scanner.risk_groups;

        for (risk, _group_cfg) in risk_groups.iter() {
            // Create a fresh ScanCache for this worker
            let cache = ScanCache::default();
            // Clone Arcs for the worker
            let rules = Arc::clone(&self.rules);
            let cfg = Arc::clone(&self.cfg_mgr);

            // Fire-and-forget the worker
            spawn_worker(rules, cfg, risk.clone(), cache, self.evt_tx.clone());
            log::info!("Worker spawned for {:?} risk", risk);
        }
    }
}
