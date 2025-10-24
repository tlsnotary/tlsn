use tlsn_core::VerifierOutput;

use super::*;

pub(crate) mod config;

/// Output of the verifier plugin.
pub struct Output {
    output: VerifierOutput,
}

pub struct VerifierParams {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    prover_url: String,
}
