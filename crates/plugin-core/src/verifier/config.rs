use tlsn::{
    config::{ProtocolConfig, ProtocolConfigBuilder},
    verifier::VerifierConfig,
};
use tlsn_core::VerifierOutput;

use super::*;

pub struct Config {
    pub verifier_params: VerifierParams,
    handlers: Vec<Handle>,
    root_store: Option<RootCertStore>,
}

impl Config {
    /// Builds and returns VerifierConfig.
    pub fn verifier_config(&self) -> VerifierConfig {
        let protocol = ProtocolConfig::builder()
            .max_sent_data(self.verifier_params.max_sent_data)
            .max_recv_data(self.verifier_params.max_recv_data)
            .build()
            .unwrap();

        let config = VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()
            .unwrap();

        // TODO how to pass protocol config?
        config
    }

    /// Returns verifier plugin output.
    pub fn output(&self, output: VerifierOutput) -> Output {
        // TODO: parse the application data when parsing with redactions
        // is supported.
        Output { output }
    }
}
