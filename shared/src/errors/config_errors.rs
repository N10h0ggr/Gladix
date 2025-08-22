use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error while accessing `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TOML parse error: {0}")]
    Parse(toml::de::Error),

    #[error("Validation error: {0}")]
    Validation(String),
}
