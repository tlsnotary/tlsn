use std::sync::Arc;

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
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the MPC-TLS connection.
    #[builder(default = "true")]
    defer_decryption_from_start: bool,
    /// Cryptography provider.
    #[builder(default, setter(into))]
    crypto_provider: Arc<CryptoProvider>,
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

    /// Returns whether the `deferred decryption` feature is toggled on from the
    /// start of the MPC-TLS connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    pub(crate) fn build_mpc_tls_config(&self) -> Config {
        Config::builder()
            .defer_decryption(self.defer_decryption_from_start)
            .max_sent(self.protocol_config.max_sent_data())
            .max_recv_online(self.protocol_config.max_recv_data_online())
            .max_recv(self.protocol_config.max_recv_data())
            .build()
            .unwrap()
    }
}
