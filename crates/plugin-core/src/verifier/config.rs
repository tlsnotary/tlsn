use crate::{
    DisclosureRule,
    verifier::{Output, VerifierParams},
};
use tlsn::{
    config::{ProtocolConfig, RootCertStore},
    verifier::VerifierConfig,
};
use tlsn_core::VerifierOutput;

/// Verifier plugin config.
#[allow(dead_code)]
pub struct Config {
    pub verifier_params: VerifierParams,
    /// Data which the prover is expected to disclose.
    pub disclose: Vec<DisclosureRule>,
    pub root_store: RootCertStore,
    pub prover_endpoint: String,
}

impl Config {
    /// Returns the prover endpoint.
    pub fn prover_endpoint(&self) -> &String {
        &self.verifier_params.prover_endpoint
    }

    /// Builds and returns [VerifierConfig].
    pub fn verifier_config(&self) -> VerifierConfig {
        VerifierConfig::builder()
            .root_store(self.root_store.clone())
            .build()
            .unwrap()
    }

    /// Validates the given protocol `config`.
    pub fn validate_protocol_config(&self, config: &ProtocolConfig) -> Result<(), ConfigError> {
        if config.max_recv_data() > self.verifier_params.max_recv_data
            || config.max_sent_data() > self.verifier_params.max_sent_data
        {
            Err(ConfigError(
                "failed to validate protocol config".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Returns verifier plugin output.
    pub fn output(&self, output: VerifierOutput) -> Output {
        Output { output }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct ConfigError(String);
