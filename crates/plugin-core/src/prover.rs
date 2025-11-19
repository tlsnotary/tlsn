//! Core types of the prover plugin.

use crate::HttpHandle;
use serde::{Deserialize, Serialize};
use tlsn_core::ProverOutput;

mod config;

pub use config::{Config, ConfigError};

/// Output of the prover plugin.
#[allow(dead_code)]
pub struct Output {
    output: ProverOutput,
    /// Plaintext exposed to the host.
    plaintext: Vec<(HttpHandle, Vec<u8>)>,
}

/// Params for protocol prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverParams {
    max_recv_data: usize,
    max_sent_data: usize,
    prove_server_identity: bool,
    pub server_dns: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    url: String,
    method: String,
    body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
}
