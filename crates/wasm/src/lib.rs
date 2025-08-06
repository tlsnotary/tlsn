//! TLSNotary WASM bindings.

#![cfg(target_arch = "wasm32")]
#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub(crate) mod io;
mod log;
pub mod prover;
#[cfg(feature = "test")]
pub mod tests;
pub mod types;
pub mod verifier;

pub use log::{LoggingConfig, LoggingLevel};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[cfg(feature = "test")]
pub use tests::*;

/// Initializes the module.
#[wasm_bindgen]
pub async fn initialize(
    logging_config: Option<LoggingConfig>,
    thread_count: usize,
) -> Result<(), JsValue> {
    log::init_logging(logging_config);

    JsFuture::from(web_spawn::start_spawner()).await?;

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
