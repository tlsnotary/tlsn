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

use tlsn_core::{transcript::Direction, CryptoProvider};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::types::{Attestation, Presentation, Reveal, Secrets};

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
