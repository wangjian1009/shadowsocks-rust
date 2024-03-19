//! Logging facilities

use crate::config::LogConfig;

mod tracing;

pub struct LogGuard {
    #[cfg(feature = "logging-file")]
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) -> LogGuard {
    tracing::init_with_config(bin_name, config)
}
