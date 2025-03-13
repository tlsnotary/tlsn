use serde::Deserialize;
use tracing::{error, Level, Metadata};
use tracing_subscriber::{
    filter::FilterFn,
    fmt::{format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_web::MakeWebConsoleWriter;
use tsify_next::Tsify;

pub(crate) fn init_logging(config: Option<LoggingConfig>) {
    let mut config = config.unwrap_or_default();

    // Default is NONE
    let fmt_span = config
        .span_events
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(FmtSpan::from)
        .fold(FmtSpan::NONE, |acc, span| acc | span);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        .with_span_events(fmt_span)
        .without_time()
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console

    tracing_subscriber::registry()
        .with(FilterFn::new(filter(config.clone())))
        .with(fmt_layer)
        .init();

    // https://github.com/rustwasm/console_error_panic_hook
    std::panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));
}

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

#[derive(Debug, Default, Clone, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct LoggingConfig {
    pub level: Option<LoggingLevel>,
    pub crate_filters: Option<Vec<CrateLogFilter>>,
    pub span_events: Option<Vec<SpanEvent>>,
}

#[derive(Debug, Clone, Tsify, Deserialize)]
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
