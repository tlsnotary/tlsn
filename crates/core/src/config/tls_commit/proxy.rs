//! Proxy-TLS commitment protocol configuration.

use crate::{config::tls_commit::NetworkSetting, connection::DnsName};
use serde::{Deserialize, Serialize};

/// Proxy-TLS commitment protocol configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyTlsConfig {
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the TLS connection.
    defer_decryption_from_start: bool,
    /// Network settings.
    network: NetworkSetting,
    /// The server name.
    server_name: DnsName,
}

impl ProxyTlsConfig {
    /// Creates a new builder.
    pub fn builder() -> ProxyTlsConfigBuilder {
        ProxyTlsConfigBuilder::default()
    }

    /// Returns whether the `deferred decryption` feature is toggled on from the
    /// start of the TLS connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    /// Returns the network settings.
    pub fn network(&self) -> NetworkSetting {
        self.network
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &DnsName {
        &self.server_name
    }
}

/// Builder for [`ProxyTlsConfig`].
#[derive(Debug, Default)]
pub struct ProxyTlsConfigBuilder {
    defer_decryption_from_start: Option<bool>,
    network: Option<NetworkSetting>,
    server_name: Option<DnsName>,
}

impl ProxyTlsConfigBuilder {
    /// Sets whether the `deferred decryption` feature is toggled on from the
    /// start of the connection.
    pub fn defer_decryption_from_start(mut self, defer_decryption_from_start: bool) -> Self {
        self.defer_decryption_from_start = Some(defer_decryption_from_start);
        self
    }

    /// Sets the network settings.
    pub fn network(mut self, network: NetworkSetting) -> Self {
        self.network = Some(network);
        self
    }

    /// Sets the server name.
    pub fn server_name(mut self, server_name: DnsName) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProxyTlsConfig, ProxyTlsConfigError> {
        let Self {
            defer_decryption_from_start,
            network,
            server_name,
        } = self;

        let defer_decryption_from_start = defer_decryption_from_start.unwrap_or(true);
        let network = network.unwrap_or_default();
        let server_name = server_name.ok_or(ProxyTlsConfigError(ErrorRepr::MissingField {
            name: "server_name",
        }))?;

        let config = ProxyTlsConfig {
            defer_decryption_from_start,
            network,
            server_name,
        };

        Ok(config)
    }
}

/// Error for [`ProxyTlsConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProxyTlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
}
