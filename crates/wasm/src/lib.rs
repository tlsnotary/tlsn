//! TLSNotary WASM bindings.

#![cfg(target_arch = "wasm32")]
#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub mod handler;
pub(crate) mod io;
mod log;
pub mod prover;
#[cfg(feature = "test")]
pub mod tests;
pub mod types;
pub mod verifier;

pub use log::{LoggingConfig, LoggingLevel};

use std::sync::OnceLock;

use tlsn_sdk_core::SharedPool;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[cfg(feature = "test")]
pub use tests::*;

/// Global context thread pool shared across all sessions.
static CONTEXT_POOL: OnceLock<SharedPool> = OnceLock::new();

/// Returns the global context pool.
///
/// # Panics
///
/// Panics if [`initialize`] has not been called.
pub(crate) fn context_pool() -> SharedPool {
    CONTEXT_POOL
        .get()
        .expect("initialize() must be called before creating a prover")
        .clone()
}

/// Initializes the module.
#[wasm_bindgen]
pub async fn initialize(
    logging_config: Option<LoggingConfig>,
    thread_count: usize,
) -> Result<(), JsValue> {
    log::init_logging(logging_config);

    JsFuture::from(web_spawn::start_spawner()).await?;

    // Initialize rayon global thread pool (CPU-bound garbling, OT, etc.).
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .spawn_handler(|thread| {
            // Drop join handle.
            let _ = web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build_global()
        .unwrap_throw();

    // Initialize context thread pool (async MPC coordination).
    use tlsn::{CustomSpawn, SpawnError};

    let mut spawn = CustomSpawn(|f: Box<dyn FnOnce() + Send>| -> Result<(), SpawnError> {
        let _ = web_spawn::spawn(f);
        Ok(())
    });
    let pool =
        SharedPool::new(thread_count, &mut spawn).map_err(|e| JsValue::from_str(&e.to_string()))?;
    CONTEXT_POOL
        .set(pool)
        .map_err(|_| JsValue::from_str("initialize() called twice"))?;

    Ok(())
}
