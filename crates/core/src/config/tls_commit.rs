//! TLS commitment configuration.

pub mod mpc;
pub mod proxy;

use serde::{Deserialize, Serialize};

use crate::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};

/// TLS commitment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitConfig<P> {
    protocol: P,
}

impl<P> TlsCommitConfig<P>
where
    P: Into<TlsCommitRequest>,
{
    /// Creates a new builder.
    pub fn builder() -> TlsCommitConfigBuilder<P> {
        TlsCommitConfigBuilder::default()
    }

    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &P {
        &self.protocol
    }
}

/// Builder for [`TlsCommitConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitConfigBuilder<P> {
    protocol: Option<P>,
}

impl<P> Default for TlsCommitConfigBuilder<P> {
    fn default() -> Self {
        Self { protocol: None }
    }
}

impl<P> TlsCommitConfigBuilder<P>
where
    P: Into<TlsCommitRequest>,
{
    /// Sets the protocol configuration.
    pub fn protocol(mut self, protocol: P) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<TlsCommitConfig<P>, TlsCommitConfigError> {
        let protocol = self
            .protocol
            .ok_or(ErrorRepr::MissingField { name: "protocol" })?;

        Ok(TlsCommitConfig { protocol })
    }
}

/// TLS commitment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TlsCommitRequest {
    /// Protocol config for mpc mode.
    Mpc(MpcTlsConfig),
    /// Protocol config for proxy mode.
    Proxy(ProxyTlsConfig),
}

impl From<MpcTlsConfig> for TlsCommitRequest {
    fn from(value: MpcTlsConfig) -> Self {
        Self::Mpc(value)
    }
}

impl From<ProxyTlsConfig> for TlsCommitRequest {
    fn from(value: ProxyTlsConfig) -> Self {
        Self::Proxy(value)
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
