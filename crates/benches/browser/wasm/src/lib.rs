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
pub use tlsn_wasm::init_logging;

use anyhow::Result;
use console_error_panic_hook::hook;
use tracing::{debug, error, info};
use tracing_subscriber::{
    fmt::{format::Pretty, time::UtcTime},
    prelude::*,
    EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_bindgen_rayon::init_thread_pool;
use web_time::Instant;
use ws_stream_wasm::WsMeta;

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
) -> Result<()> {
    info!("starting main");

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

    info!("expecting config from the native component");

    let cfg: Config = native_io.expect_next().await?;

    let start_time = Instant::now();
    run_prover(
        cfg.upload_size,
        cfg.download_size,
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
