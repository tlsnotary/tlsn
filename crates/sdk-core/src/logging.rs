//! Platform-agnostic logging configuration and filtering.
//!
//! This module provides logging types and filter logic that can be reused
//! across platforms (WASM, iOS, Android, native). Each platform provides
//! its own tracing Layer/writer — this module only handles configuration.

use serde::Deserialize;
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::format::FmtSpan;

/// Logging verbosity level.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
pub enum LoggingLevel {
    /// Disable all logging for this target.
    Off,
    /// Most verbose — includes all messages.
    Trace,
    /// Detailed debugging information.
    Debug,
    /// Informational messages (default).
    #[default]
    Info,
    /// Warnings only.
    Warn,
    /// Errors only.
    Error,
}

impl LoggingLevel {
    /// Returns true if this level disables all logging.
    pub fn is_off(&self) -> bool {
        matches!(self, LoggingLevel::Off)
    }
}

impl From<LoggingLevel> for Level {
    fn from(value: LoggingLevel) -> Self {
        match value {
            // Off maps to ERROR as a fallback, but is_off() should be checked first.
            LoggingLevel::Off => Level::ERROR,
            LoggingLevel::Trace => Level::TRACE,
            LoggingLevel::Debug => Level::DEBUG,
            LoggingLevel::Info => Level::INFO,
            LoggingLevel::Warn => Level::WARN,
            LoggingLevel::Error => Level::ERROR,
        }
    }
}

/// Span lifecycle events to log.
#[derive(Debug, Clone, Copy, Deserialize)]
pub enum SpanEvent {
    /// Log when a span is created.
    New,
    /// Log when a span is closed.
    Close,
    /// Log when a span becomes active.
    Active,
}

impl From<SpanEvent> for FmtSpan {
    fn from(value: SpanEvent) -> Self {
        match value {
            SpanEvent::New => FmtSpan::NEW,
            SpanEvent::Close => FmtSpan::CLOSE,
            SpanEvent::Active => FmtSpan::ACTIVE,
        }
    }
}

/// Top-level logging configuration.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Global default log level.
    pub level: Option<LoggingLevel>,
    /// Per-crate log level overrides.
    pub crate_filters: Option<Vec<CrateLogFilter>>,
    /// Which span lifecycle events to log.
    pub span_events: Option<Vec<SpanEvent>>,
}

/// Per-crate log level override.
#[derive(Debug, Clone, Deserialize)]
pub struct CrateLogFilter {
    /// Log level for this crate.
    pub level: LoggingLevel,
    /// Crate name to match (case-insensitive).
    pub name: String,
}

/// Creates a filter function from a [`LoggingConfig`].
///
/// The returned closure checks each tracing event's target against the
/// configured crate filters (case-insensitive match on the first path
/// segment). Events that don't match any filter use the global default level.
pub fn filter(config: LoggingConfig) -> impl Fn(&Metadata) -> bool {
    let default_level = config.level.unwrap_or(LoggingLevel::Info);
    let crate_filters = config
        .crate_filters
        .unwrap_or_default()
        .into_iter()
        .map(|filter| (filter.name, filter.level))
        .collect::<Vec<_>>();

    move |meta| {
        let logging_level = if let Some(crate_name) = meta.target().split("::").next() {
            crate_filters
                .iter()
                .find_map(|(filter_name, filter_level)| {
                    if crate_name.eq_ignore_ascii_case(filter_name) {
                        Some(*filter_level)
                    } else {
                        None
                    }
                })
                .unwrap_or(default_level)
        } else {
            default_level
        };

        // Off disables all logging for this target.
        if logging_level.is_off() {
            return false;
        }

        meta.level() <= &Level::from(logging_level)
    }
}
