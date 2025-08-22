//! signatures.rs
//!
//! Loader for YARA signature files using the `yara_x` crate.

use std::fs;
use std::fs::File;
use std::io::{self, Read};
use thiserror::Error;
use yara_x::errors::CompileError;
use yara_x::*;
use zip::ZipArchive;

#[derive(Debug, Error)]
pub enum SignaturesError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Error unzipping the file: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Error with Yara rule: {0}")]
    Yara(#[from] CompileError),
}

pub enum SignatureSource {
    File(String),
    Zip(String),
}

/// Container for YARA rules (raw and compiled).
pub struct Signatures {}

impl Signatures {
    /// Load YARA rules from a local directory (`rules/yara/`), or fetch a ZIP archive from `url`.
    /// Aborts if neither source is available or compilation fails.
    pub fn load(source: SignatureSource) -> Result<Rules, SignaturesError> {
        let mut compiler = Compiler::new();
        match source {
            SignatureSource::File(file_path) => Self::parse_file(&mut compiler, file_path)?,
            SignatureSource::Zip(zip_path) => Self::parse_zip(&mut compiler, zip_path)?,
        };
        let rules = compiler.build();

        Ok(rules)
    }

    fn parse_file(compiler: &mut Compiler, file_path: String) -> Result<(), SignaturesError> {
        let rule = fs::read(&file_path)?;
        compiler.add_source(rule.as_slice())?;
        Ok(())
    }

    fn parse_zip(compiler: &mut Compiler, zip_path: String) -> Result<(), SignaturesError> {
        let file = File::open(&zip_path)?;
        let mut archive = ZipArchive::new(file)?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if entry.is_dir() {
                continue;
            }

            if entry.name().ends_with(".yar") || entry.name().ends_with(".yara") {
                let mut buf = vec![];
                entry.read_to_end(&mut buf)?;
                compiler.add_source(buf.as_slice())?;
            }
        }

        Ok(())
    }
}
