use serde::Deserialize;
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::format::FmtSpan;
use tsify_next::Tsify;

#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum LoggingLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LoggingLevel> for Level {
    fn from(value: LoggingLevel) -> Self {
        match value {
            LoggingLevel::Trace => Level::TRACE,
            LoggingLevel::Debug => Level::DEBUG,
            LoggingLevel::Info => Level::INFO,
            LoggingLevel::Warn => Level::WARN,
            LoggingLevel::Error => Level::ERROR,
        }
    }
}

#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum SpanEvent {
    New,
    Close,
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

#[derive(Debug, Default, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct LoggingConfig {
    pub level: Option<LoggingLevel>,
    pub crate_filters: Option<Vec<CrateLogFilter>>,
    pub span_events: Option<Vec<SpanEvent>>,
}

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct CrateLogFilter {
    pub level: LoggingLevel,
    pub name: String,
}

pub(crate) fn filter(config: LoggingConfig) -> impl Fn(&Metadata) -> bool {
    let default_level: Level = config.level.unwrap_or(LoggingLevel::Info).into();
    let crate_filters = config
        .crate_filters
        .unwrap_or_default()
        .into_iter()
        .map(|filter| (filter.name, Level::from(filter.level)))
        .collect::<Vec<_>>();

    move |meta| {
        let level = if let Some(crate_name) = meta.target().split("::").next() {
            crate_filters
                .iter()
                .find_map(|(filter_name, filter_level)| {
                    if crate_name.eq_ignore_ascii_case(filter_name) {
                        Some(filter_level)
                    } else {
                        None
                    }
                })
                .unwrap_or(&default_level)
        } else {
            &default_level
        };

        meta.level() <= level
    }
}
