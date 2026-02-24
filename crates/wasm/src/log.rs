//! WASM-specific logging initialization.
//!
//! Provides tsify-annotated types for the wasm_bindgen API surface and
//! delegates filtering to [`tlsn_sdk_core::logging`]. Console output is
//! handled by [`wasm_tracing::WASMLayer`] (no `web-sys` dependency).

use serde::Deserialize;
use tracing::Level;
use tracing_subscriber::{filter::FilterFn, layer::SubscriberExt, util::SubscriberInitExt};
use tsify_next::Tsify;
use wasm_tracing::{WASMLayer, WASMLayerConfigBuilder};

// ---------------------------------------------------------------------------
// Tsify wrapper types (wasm_bindgen API surface)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum LoggingLevel {
    Off,
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum SpanEvent {
    New,
    Close,
    Active,
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

// ---------------------------------------------------------------------------
// Conversions to sdk-core types
// ---------------------------------------------------------------------------

impl From<LoggingLevel> for tlsn_sdk_core::logging::LoggingLevel {
    fn from(val: LoggingLevel) -> Self {
        match val {
            LoggingLevel::Off => Self::Off,
            LoggingLevel::Trace => Self::Trace,
            LoggingLevel::Debug => Self::Debug,
            LoggingLevel::Info => Self::Info,
            LoggingLevel::Warn => Self::Warn,
            LoggingLevel::Error => Self::Error,
        }
    }
}

impl From<SpanEvent> for tlsn_sdk_core::logging::SpanEvent {
    fn from(val: SpanEvent) -> Self {
        match val {
            SpanEvent::New => Self::New,
            SpanEvent::Close => Self::Close,
            SpanEvent::Active => Self::Active,
        }
    }
}

impl From<CrateLogFilter> for tlsn_sdk_core::logging::CrateLogFilter {
    fn from(val: CrateLogFilter) -> Self {
        Self {
            level: val.level.into(),
            name: val.name,
        }
    }
}

impl From<LoggingConfig> for tlsn_sdk_core::logging::LoggingConfig {
    fn from(val: LoggingConfig) -> Self {
        Self {
            level: val.level.map(Into::into),
            crate_filters: val
                .crate_filters
                .map(|v| v.into_iter().map(Into::into).collect()),
            span_events: val
                .span_events
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

pub(crate) fn init_logging(config: Option<LoggingConfig>) {
    // Convert to platform-agnostic config and build the filter.
    let core_config: tlsn_sdk_core::logging::LoggingConfig = config.unwrap_or_default().into();

    let wasm_layer_config = WASMLayerConfigBuilder::new()
        .set_report_logs_in_timings(false) // avoid performance.mark (Node.js compat)
        .set_max_level(Level::TRACE) // let FilterFn handle actual filtering
        .build();

    tracing_subscriber::registry()
        .with(FilterFn::new(tlsn_sdk_core::logging::filter(core_config)))
        .with(WASMLayer::new(wasm_layer_config))
        .init();

    // WASM-specific panic hook.
    std::panic::set_hook(Box::new(|info| {
        tracing::error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));
}
