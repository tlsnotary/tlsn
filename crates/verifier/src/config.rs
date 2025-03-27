use std::{
    fmt::{Debug, Formatter, Result},
    sync::Arc,
};

use mpc_tls::Config;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::CryptoProvider;

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    protocol_config_validator: ProtocolConfigValidator,
    /// Cryptography provider.
    #[builder(default, setter(into))]
    crypto_provider: Arc<CryptoProvider>,
}

impl Debug for VerifierConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("VerifierConfig")
            .field("protocol_config_validator", &self.protocol_config_validator)
            .finish_non_exhaustive()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the protocol configuration validator.
    pub fn protocol_config_validator(&self) -> &ProtocolConfigValidator {
        &self.protocol_config_validator
    }

    /// Returns the cryptography provider.
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    pub(crate) fn build_mpc_tls_config(&self, protocol_config: &ProtocolConfig) -> Config {
        Config::builder()
            .max_sent(protocol_config.max_sent_data())
            .max_recv_online(protocol_config.max_recv_data_online())
            .max_recv(protocol_config.max_recv_data())
            .build()
            .unwrap()
    }
}
