//! TLSNotary WASM bindings.

#![cfg(target_arch = "wasm32")]
#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub mod handler;
pub(crate) mod io;
mod log;
pub mod prover;
pub mod session;
mod strict;
pub mod types;
pub mod verifier;

pub use log::{LoggingConfig, LoggingLevel};
pub use session::SessionOptions;

use tsify::Ts;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Initializes the module.
#[wasm_bindgen]
pub async fn initialize(
    logging_config: Option<Ts<LoggingConfig>>,
    thread_count: usize,
) -> Result<(), JsError> {
    let logging_config = logging_config
        .map(|config| {
            config
                .to_rust()
                .map_err(|err| JsError::new(&err.to_string()))
        })
        .transpose()?;
    log::init_logging(logging_config);

    JsFuture::from(web_spawn::start_spawner())
        .await
        .map_err(|err| JsError::new(&format!("failed to start spawner: {err:?}")))?;

    // Initialize rayon global thread pool.
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .spawn_handler(|thread| {
            // Drop join handle.
            let _ = web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build_global()
        .unwrap_throw();

    Ok(())
}
