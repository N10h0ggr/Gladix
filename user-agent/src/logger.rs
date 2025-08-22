use flexi_logger::{DeferredNow, FileSpec, Logger, LoggerHandle, WriteMode};
use log::Record;
use std::io::Write;
use std::thread;

/// Initializes the logger with custom formatting.
pub fn init_logger() -> Result<LoggerHandle, Box<dyn std::error::Error>> {
    let handle = Logger::try_with_str("user_agent=info")?
        .log_to_file(FileSpec::default().directory("logs").suppress_timestamp())
        .append()
        .write_mode(WriteMode::BufferAndFlush)
        .format(log_format)
        .start()?;
    Ok(handle)
}

/// Custom log line format: includes timestamp, level, source file/line, thread name, and message.
fn log_format(w: &mut dyn Write, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
    write!(
        w,
        "{} [{:<5}] [{}:{}] [{}] {}",
        now.format("%Y-%m-%d %H:%M:%S"),
        record.level(),
        record.file().unwrap_or("<unknown>"),
        record.line().unwrap_or(0),
        thread::current().name().unwrap_or("<unnamed>"),
        &record.args()
    )
}
