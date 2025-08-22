use std::path::PathBuf;
use thiserror::Error;
use yara_x::errors::{CompileError, ScanError};

/// All errors that can occur in the scanner subsystem.
#[derive(Debug, Error)]
pub enum ScannerError {
    /// Failure to read or stat a file
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failure during YARA rule compilation
    #[error(transparent)]
    Compile(#[from] CompileError),

    /// A scan operation failed
    #[error("YARA scan failed on `{path}`: {source}")]
    Scan {
        path: PathBuf,
        #[source]
        source: ScanError,
    },

    /// Something went wrong updating the cache
    #[error("Cache update failed for `{0}`: {1}")]
    Cache(PathBuf, String),
}
