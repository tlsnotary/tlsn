//! Core types of the verifier plugin.

use tlsn_core::VerifierOutput;

mod config;

pub use config::{Config, ConfigError};

/// Output of the verifier plugin.
#[allow(dead_code)]
pub struct Output {
    output: VerifierOutput,
}

/// Params for protocol verifier.
pub struct VerifierParams {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub prover_endpoint: String,
}
