use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use shared::errors::ConfigError;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, RwLock},
    thread,
};
use strum_macros;

/// Full application configuration, loaded from TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Database-related settings
    pub database: DatabaseConfig,
    /// Scanner-specific settings, including nested risk groups
    pub scanner: ScannerConfig,
}

/// Database configuration section `[database]`.
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// Path to the SQLite file
    pub path: String,
    /// Whether to purge existing data on restart
    pub purge_on_restart: bool,
    /// SQLite synchronous mode (OFF, NORMAL, FULL, etc.)
    pub synchronous: SynchronousMode,
    /// Max journal size before auto-truncate
    pub journal_size_limit: u64,
    /// Seconds between WAL checkpoints
    pub checkpoint_seconds: u64,
    /// Time-to-live for old events (seconds)
    pub ttl_seconds: u64,
    /// Batch size for in-memory buffering
    pub batch_size: u64,
}

/// Modes for SQLite's `synchronous` pragma.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[derive(PartialEq)]
pub enum SynchronousMode {
    Off,
    Normal,
    Full,
    Extra,
}

/// Scanner configuration `[scanner]` and its nested `risk_groups`.
#[derive(Debug, Deserialize, Clone)]
pub struct ScannerConfig {
    /// Maximum file size (MB)
    pub max_file_size_mb: u64,
    /// File extensions to include
    pub extensions: Vec<String>,
    /// Path to YARA rules file (TOML key `rules`)
    #[serde(rename = "rules")]
    pub rule_path: String,
    /// Risk-group settings under `[scanner.risk_groups]`
    pub risk_groups: HashMap<DirectoryRisk, RiskGroupConfig>,
}

/// Risk levels for directories (lowercase in TOML).
#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
#[derive(strum_macros::Display)]
pub enum DirectoryRisk {
    High,
    Medium,
    Low,
    Special,
}

/// Settings for each directory risk group.
#[derive(Debug, Deserialize, Clone)]
pub struct RiskGroupConfig {
    /// Optional scan interval (seconds)
    pub scheduled_interval: Option<u64>,
    /// Directories included in this group
    pub directories: Vec<PathBuf>,
}

impl Config {
    /// Load, parse, and validate a `Config` from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        // Read file
        let s = fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        // Parse TOML
        let cfg: Config = toml::from_str(&s).map_err(ConfigError::Parse)?;

        // Validate scanner section
        if cfg.scanner.extensions.is_empty() {
            return Err(ConfigError::Validation(
                "scanner.extensions must have at least one entry".into(),
            ));
        }
        if cfg.scanner.max_file_size_mb == 0 {
            return Err(ConfigError::Validation(
                "scanner.max_file_size_mb must be > 0".into(),
            ));
        }
        // Ensure rules file exists
        let rp = PathBuf::from(&cfg.scanner.rule_path);
        fs::metadata(&rp).map_err(|e| ConfigError::Io {
            path: rp,
            source: e,
        })?;

        // Validate scanner.risk_groups contains all levels
        cfg.validate_risk_groups()?;
        Ok(cfg)
    }

    /// Ensure each `DirectoryRisk` variant is present under `scanner.risk_groups`.
    fn validate_risk_groups(&self) -> Result<(), ConfigError> {
        let expected = [
            DirectoryRisk::High,
            DirectoryRisk::Medium,
            DirectoryRisk::Low,
            DirectoryRisk::Special,
        ];
        let missing: Vec<_> = expected
            .iter()
            .filter(|r| !self.scanner.risk_groups.contains_key(r))
            .map(|r| format!("{:?}", r))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(format!(
                "Missing scanner.risk_groups for: {}",
                missing.join(", ")
            )))
        }
    }

    #[cfg(test)]
    pub fn from_str(toml: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml).map_err(ConfigError::Parse)
    }
}

/// Manages a live-updating `Config` via file-watcher.
pub struct ConfigManager {
    inner: Arc<RwLock<Config>>,
    _watcher: RecommendedWatcher,
}

impl ConfigManager {
    pub fn new(path: &Path) -> Result<Self, ConfigError> {
        let cfg = Config::load(path)?;
        let shared = Arc::new(RwLock::new(cfg));
        let (tx, rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            tx.clone(),
            notify::Config::default().with_poll_interval(std::time::Duration::from_secs(1))
        ).map_err(|e| ConfigError::Validation(format!("Watcher error: {}", e)))?;
        
        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::Validation(format!("Watch error: {}", e)))?;

        // Spawn thread to reload on modify events
        let cfg_path = path.to_path_buf();
        let shared_clone = Arc::clone(&shared);
        
        let config_thread = thread::Builder::new().name("config_watcher".to_string());
        config_thread.spawn(move || {
            for evt in rx {
                if let Ok(event) = evt {
                    if let EventKind::Modify(_) = event.kind {
                        if let Ok(new_cfg) = Config::load(&cfg_path) {
                            *shared_clone.write().unwrap() = new_cfg;
                            log::info!("Config reloaded");
                        } else {
                            log::error!("Failed to reload config");
                        }
                    }
                }
            }
        }).unwrap(); //TODO: Handle error

        Ok(ConfigManager {
            inner: shared,
            _watcher: watcher,
        })
    }

    /// Snapshot-like read of the current config
    pub fn get(&self) -> Config {
        self.inner.read().unwrap().clone()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DirectoryRisk::{High, Low, Medium, Special};
    use std::path::PathBuf;

    const SAMPLE: &str = r#"
[database]
    path               = "telemetry.db"
    purge_on_restart   = true
    synchronous        = "NORMAL"
    journal_size_limit = 20000000
    checkpoint_seconds = 30
    ttl_seconds        = 3600
    batch_size         = 1000

    [scanner]
    max_file_size_mb = 50
    extensions = ["exe", "dll", "sys", "ocx"]
    rules = "C:\\Users\\Noel\\RustroverProjects\\av_scanner\\src\\yara-rules-core.yar"

    [scanner.risk_groups.high]
    scheduled_interval = 62
    directories = ["C:\\Users\\Noel\\Downloads"]

    [scanner.risk_groups.medium]
    scheduled_interval = 100
    directories = ["C:\\Users\\Noel\\Documents"]

    [scanner.risk_groups.low]
    directories = ["C:\\Users\\Noel\\Documents"]

    [scanner.risk_groups.special]
    directories = ["C:\\Users\\Noel\\Documents"]
    "#;

    #[test]
    fn parse_full_config() {
        let cfg = Config::from_str(SAMPLE).expect("should parse full sample");

        // database assertions
        assert_eq!(cfg.database.path, "telemetry.db");
        assert!(cfg.database.purge_on_restart);
        assert_eq!(cfg.database.synchronous, SynchronousMode::Normal);
        assert_eq!(cfg.database.journal_size_limit, 20_000_000);
        assert_eq!(cfg.database.checkpoint_seconds, 30);
        assert_eq!(cfg.database.ttl_seconds, 3600);
        assert_eq!(cfg.database.batch_size, 1000);

        // scanner assertions
        assert_eq!(cfg.scanner.max_file_size_mb, 50);
        assert_eq!(cfg.scanner.extensions, vec!["exe", "dll", "sys", "ocx"]);
        assert_eq!(
            cfg.scanner.rule_path,
            "C:\\Users\\Noel\\RustroverProjects\\av_scanner\\src\\yara-rules-core.yar"
        );

        // risk groups
        let high = &cfg.scanner.risk_groups[&High];
        assert_eq!(high.scheduled_interval, Some(62));
        assert_eq!(
            high.directories,
            vec![PathBuf::from("C:\\Users\\Noel\\Downloads")]
        );

        let medium = &cfg.scanner.risk_groups[&Medium];
        assert_eq!(medium.scheduled_interval, Some(100));
        assert_eq!(
            medium.directories,
            vec![PathBuf::from("C:\\Users\\Noel\\Documents")]
        );

        let low = &cfg.scanner.risk_groups[&Low];
        assert_eq!(low.scheduled_interval, None);
        assert_eq!(
            low.directories,
            vec![PathBuf::from("C:\\Users\\Noel\\Documents")]
        );

        let special = &cfg.scanner.risk_groups[&Special];
        assert_eq!(special.scheduled_interval, None);
        assert_eq!(
            special.directories,
            vec![PathBuf::from("C:\\Users\\Noel\\Documents")]
        );
    }

    #[test]
    fn missing_database_section() {
        let toml = r#"
        [scanner]
        max_file_size_mb = 10
        extensions = ["txt"]
        rules = "rules.yar"
        [scanner.risk_groups.high]
        directories = ["."]
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap_err(),
            ConfigError::Parse(_)
        ));
    }

    #[test]
    fn missing_scanner_section() {
        let toml = r#"
        [database]
        path = "db.sqlite"
        purge_on_restart = false
        synchronous = "OFF"
        journal_size_limit = 100000
        checkpoint_seconds = 10
        ttl_seconds = 60
        batch_size = 100
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap_err(),
            ConfigError::Parse(_)
        ));
    }

    #[test]
    fn missing_risk_groups() {
        let toml = r#"
        [database]
        path = "db.sqlite"
        purge_on_restart = false
        synchronous = "OFF"
        journal_size_limit = 100000
        checkpoint_seconds = 10
        ttl_seconds = 60
        batch_size = 100

        [scanner]
        max_file_size_mb = 10
        extensions = ["txt"]
        rules = "rules.yar"
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap_err(),
            ConfigError::Parse(_)
        ));
    }

    #[test]
    fn invalid_synchronous_mode() {
        let toml = r#"
        [database]
        path = "db.sqlite"
        purge_on_restart = true
        synchronous = "FAST"
        journal_size_limit = 1000
        checkpoint_seconds = 5
        ttl_seconds = 100
        batch_size = 50

        [scanner]
        max_file_size_mb = 1
        extensions = ["txt"]
        rules = "rules.yar"

        [scanner.risk_groups.high]
        directories = ["."]
        [scanner.risk_groups.medium]
        directories = ["."]
        [scanner.risk_groups.low]
        directories = ["."]
        [scanner.risk_groups.special]
        directories = ["."]
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap_err(),
            ConfigError::Parse(_)
        ));
    }
}
