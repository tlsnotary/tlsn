//! Contains the wasm component of the browser prover.
//!
//! Conceptually the browser prover consists of the native and the wasm components.

use std::panic;

use serio::{stream::IoStreamExt, SinkExt as _};
use tlsn_benches_browser_core::{
    msg::{Config, Runtime},
    FramedIo,
};
use tlsn_benches_library::run_prover;

use anyhow;
use console_error_panic_hook;
use tracing::{debug, error};
use tracing_subscriber::{
    fmt::{format::Pretty, time::UtcTime},
    prelude::*,
    EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys;
use web_time::Instant;
use ws_stream_wasm::WsMeta;

macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[wasm_bindgen]
pub async fn wasm_main(
    ws_ip: String,
    ws_port: u16,
    wasm_to_server_port: u16,
    wasm_to_verifier_port: u16,
    wasm_to_native_port: u16,
) -> Result<(), JsError> {
    // Wrapping main() since wasm_bindgen doesn't support anyhow.
    main(
        ws_ip,
        ws_port,
        wasm_to_server_port,
        wasm_to_verifier_port,
        wasm_to_native_port,
    )
    .await
    .map_err(|err| JsError::new(&err.to_string()))
}

pub async fn main(
    ws_ip: String,
    ws_port: u16,
    wasm_to_server_port: u16,
    wasm_to_verifier_port: u16,
    wasm_to_native_port: u16,
) -> anyhow::Result<()> {
    log!("starting main");

    // Connect to the server.
    let (_, server_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_server_port
        ),
        None,
    )
    .await?;
    let server_io = server_io_ws.into_io();

    // Connect to the verifier.
    let (_, verifier_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_verifier_port
        ),
        None,
    )
    .await?;
    let verifier_io = verifier_io_ws.into_io();

    log!("connected to ws");

    // Connect to the native component of the browser prover.
    let (_, native_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_native_port
        ),
        None,
    )
    .await?;
    let mut native_io = FramedIo::new(Box::new(native_io_ws.into_io()));
    let cfg: Config = native_io.expect_next().await?;

    let start_time = Instant::now();
    run_prover(
        cfg.upload_size as usize,
        cfg.download_size as usize,
        cfg.defer_decryption,
        Box::new(verifier_io),
        Box::new(server_io),
    )
    .await?;

    native_io
        .send(Runtime(start_time.elapsed().as_secs()))
        .await?;

    Ok(())
}

#[wasm_bindgen]
pub fn setup_tracing_web(logging_filter: &str) {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console
    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    let filter_layer = EnvFilter::builder()
        .parse(logging_filter)
        .unwrap_or_default();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(perf_layer)
        .init(); // Install these as subscribers to tracing events

    // https://github.com/rustwasm/console_error_panic_hook
    panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));

    debug!("🪵 Logging set up 🪵")
}
