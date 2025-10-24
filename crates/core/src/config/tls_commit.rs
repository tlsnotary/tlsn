//! TLS commitment configuration.

pub mod mpc;

use serde::{Deserialize, Serialize};

/// TLS commitment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitConfig {
    protocol: TlsCommitProtocolConfig,
}

impl TlsCommitConfig {
    /// Creates a new builder.
    pub fn builder() -> TlsCommitConfigBuilder {
        TlsCommitConfigBuilder::default()
    }

    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &TlsCommitProtocolConfig {
        &self.protocol
    }

    /// Returns a TLS commitment request.
    pub fn to_request(&self) -> TlsCommitRequest {
        TlsCommitRequest {
            config: self.protocol.clone(),
        }
    }
}

/// Builder for [`TlsCommitConfig`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsCommitConfigBuilder {
    protocol: Option<TlsCommitProtocolConfig>,
}

impl TlsCommitConfigBuilder {
    /// Sets the protocol configuration.
    pub fn protocol<C>(mut self, protocol: C) -> Self
    where
        C: Into<TlsCommitProtocolConfig>,
    {
        self.protocol = Some(protocol.into());
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<TlsCommitConfig, TlsCommitConfigError> {
        let protocol = self
            .protocol
            .ok_or(ErrorRepr::MissingField { name: "protocol" })?;

        Ok(TlsCommitConfig { protocol })
    }
}

/// TLS commitment protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TlsCommitProtocolConfig {
    /// MPC-TLS configuration.
    Mpc(mpc::MpcTlsConfig),
}

impl From<mpc::MpcTlsConfig> for TlsCommitProtocolConfig {
    fn from(config: mpc::MpcTlsConfig) -> Self {
        Self::Mpc(config)
    }
}

/// TLS commitment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitRequest {
    config: TlsCommitProtocolConfig,
}

impl TlsCommitRequest {
    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &TlsCommitProtocolConfig {
        &self.config
    }
}

/// Error for [`TlsCommitConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsCommitConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
}
