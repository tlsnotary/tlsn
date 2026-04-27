//! TLS commitment configuration.

pub mod mpc;
pub mod proxy;

use serde::{Deserialize, Serialize};

/// TLS commitment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitConfig<P> {
    protocol: P,
}

impl<P: Clone> TlsCommitConfig<P> {
    /// Creates a new builder.
    pub fn builder() -> TlsCommitConfigBuilder<P> {
        TlsCommitConfigBuilder::default()
    }

    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &P {
        &self.protocol
    }

    /// Returns a TLS commitment request.
    pub fn to_request(&self) -> TlsCommitRequest<P> {
        TlsCommitRequest {
            config: self.protocol.clone(),
        }
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

impl<P> TlsCommitConfigBuilder<P> {
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
pub struct TlsCommitRequest<P> {
    config: P,
}

impl<P> TlsCommitRequest<P> {
    /// Creates a new commit request.
    pub fn new(config: P) -> Self {
        Self { config }
    }

    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &P {
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
