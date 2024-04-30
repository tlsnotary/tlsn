//! TLSNotary WASM bindings.

// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![forbid(unsafe_code)]

pub(crate) mod io;
pub mod prover;
pub mod verifier;

use tracing::error;
use tracing_subscriber::{
    fmt::{format::Pretty, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn setup_tracing_web() {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console

    //let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with(fmt_layer)
        .init(); // Install these as subscribers to tracing events

    // https://github.com/rustwasm/console_error_panic_hook
    std::panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));
}
