//! Proxy-TLS commitment protocol configuration.

use crate::connection::DnsName;
use serde::{Deserialize, Serialize};

/// Proxy-TLS commitment protocol configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyTlsConfig {
    /// The server name.
    server_name: DnsName,
}

impl ProxyTlsConfig {
    /// Creates a new builder.
    pub fn builder() -> ProxyTlsConfigBuilder {
        ProxyTlsConfigBuilder::default()
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &DnsName {
        &self.server_name
    }
}

/// Builder for [`ProxyTlsConfig`].
#[derive(Debug, Default)]
pub struct ProxyTlsConfigBuilder {
    server_name: Option<DnsName>,
}

impl ProxyTlsConfigBuilder {
    /// Sets the server name.
    pub fn server_name(mut self, server_name: DnsName) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProxyTlsConfig, ProxyTlsConfigError> {
        let server_name = self
            .server_name
            .ok_or(ProxyTlsConfigError(ErrorRepr::MissingField {
                name: "server_name",
            }))?;

        let config = ProxyTlsConfig { server_name };
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
