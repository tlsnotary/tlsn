use std::sync::Arc;

use hmac_sha256::Mode as PrfConfig;
use mpc_tls::Config;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{connection::ServerName, CryptoProvider};

/// Configuration for the prover
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct ProverConfig {
    /// The server DNS name.
    #[builder(setter(into))]
    server_name: ServerName,
    /// Protocol configuration to be checked with the verifier.
    protocol_config: ProtocolConfig,
    /// Cryptography provider.
    #[builder(default, setter(into))]
    crypto_provider: Arc<CryptoProvider>,
    /// Configuration options for the PRF.
    #[builder(default)]
    prf: PrfConfig,
}

impl ProverConfig {
    /// Create a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns the server DNS name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the crypto provider.
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    /// Returns the protocol configuration.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    pub(crate) fn build_mpc_tls_config(&self) -> Config {
        let mut builder = Config::builder();

        builder
            .defer_decryption(self.protocol_config.defer_decryption_from_start())
            .max_sent(self.protocol_config.max_sent_data())
            .max_recv_online(self.protocol_config.max_recv_data_online())
            .max_recv(self.protocol_config.max_recv_data())
            .prf(self.prf);

        if let Some(max_sent_records) = self.protocol_config.max_sent_records() {
            builder.max_sent_records(max_sent_records);
        }

        if let Some(max_recv_records) = self.protocol_config.max_recv_records() {
            builder.max_recv_records(max_recv_records);
        }

        builder.build().unwrap()
    }
}
