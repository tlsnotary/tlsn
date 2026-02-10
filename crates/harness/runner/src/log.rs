use serde::Serialize;

/// Logging configuration for WASM, matching tlsn-wasm's LoggingConfig.
#[derive(Debug, Serialize)]
pub(crate) struct LoggingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<LoggingLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crate_filters: Option<Vec<CrateLogFilter>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum LoggingLevel {
    Off,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Serialize)]
pub(crate) struct CrateLogFilter {
    name: String,
    level: LoggingLevel,
}

/// Parses a RUST_LOG string into a LoggingConfig.
///
/// Supports formats like:
/// - `debug` -> level: Debug
/// - `warn,tlsn=debug` -> level: Warn, crate_filters: [{name: "tlsn", level:
///   Debug}]
pub(crate) fn parse_rust_log(rust_log: &str) -> LoggingConfig {
    let mut level = None;
    let mut crate_filters = Vec::new();

    for directive in rust_log.split(',') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        if let Some((crate_name, crate_level)) = directive.split_once('=') {
            // Crate-specific directive: `crate_name=level`
            if let Some(parsed_level) = parse_level(crate_level) {
                crate_filters.push(CrateLogFilter {
                    name: crate_name.to_string(),
                    level: parsed_level,
                });
            } else {
                eprintln!(
                    "warning: unknown log level '{}' for crate '{}' (browser target only supports off/trace/debug/info/warn/error)",
                    crate_level, crate_name
                );
            }
        } else {
            // Global level directive
            if let Some(parsed_level) = parse_level(directive) {
                level = Some(parsed_level);
            } else {
                eprintln!(
                    "warning: unknown log level '{}' (browser target only supports off/trace/debug/info/warn/error)",
                    directive
                );
            }
        }
    }

    LoggingConfig {
        level,
        crate_filters: if crate_filters.is_empty() {
            None
        } else {
            Some(crate_filters)
        },
    }
}

fn parse_level(s: &str) -> Option<LoggingLevel> {
    match s.to_lowercase().as_str() {
        "off" => Some(LoggingLevel::Off),
        "trace" => Some(LoggingLevel::Trace),
        "debug" => Some(LoggingLevel::Debug),
        "info" => Some(LoggingLevel::Info),
        "warn" | "warning" => Some(LoggingLevel::Warn),
        "error" => Some(LoggingLevel::Error),
        _ => None,
    }
}
