//! TLSNotary WASM bindings.

#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub(crate) mod io;
mod log;
pub mod prover;
#[cfg(feature = "test")]
pub mod tests;
pub mod types;
pub mod verifier;

use log::LoggingConfig;
use tlsn_core::{transcript::Direction, CryptoProvider};
use tracing::error;
use tracing_subscriber::{
    filter::FilterFn,
    fmt::{format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_web::MakeWebConsoleWriter;
use wasm_bindgen::prelude::*;

use crate::types::{Attestation, Presentation, Reveal, Secrets};

#[cfg(feature = "test")]
pub use tests::*;

#[cfg(target_arch = "wasm32")]
pub use wasm_bindgen_rayon::init_thread_pool;

/// Initializes logging.
#[wasm_bindgen]
pub fn init_logging(config: Option<LoggingConfig>) {
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
        .with(FilterFn::new(log::filter(config)))
        .with(fmt_layer)
        .init();

    // https://github.com/rustwasm/console_error_panic_hook
    std::panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));
}

/// Builds a presentation.
#[wasm_bindgen]
pub fn build_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    reveal: Reveal,
) -> Result<Presentation, JsError> {
    let provider = CryptoProvider::default();

    let mut builder = attestation.0.presentation_builder(&provider);

    builder.identity_proof(secrets.0.identity_proof());

    let mut proof_builder = secrets.0.transcript_proof_builder();

    for range in reveal.sent.iter() {
        proof_builder.reveal(range, Direction::Sent)?;
    }

    for range in reveal.recv.iter() {
        proof_builder.reveal(range, Direction::Received)?;
    }

    builder.transcript_proof(proof_builder.build()?);

    builder
        .build()
        .map(Presentation::from)
        .map_err(JsError::from)
}
