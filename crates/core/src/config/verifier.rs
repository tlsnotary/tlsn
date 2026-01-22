//! Verifier configuration.

use serde::{Deserialize, Serialize};

use crate::{config::tls_commit::TlsCommitProtocolConfig, webpki::RootCertStore};

/// Verifier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    root_store: RootCertStore,
    mode: Mode,
}

impl VerifierConfig {
    /// Creates a new builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the root certificate store.
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    /// Returns the accepted mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }
}

/// Builder for [`VerifierConfig`].
#[derive(Debug, Default)]
pub struct VerifierConfigBuilder {
    root_store: Option<RootCertStore>,
    mode: Mode,
}

impl VerifierConfigBuilder {
    /// Sets the root certificate store.
    pub fn root_store(mut self, root_store: RootCertStore) -> Self {
        self.root_store = Some(root_store);
        self
    }

    /// Uses multi-party computation for creating commitments.
    pub fn mpc(mut self) -> Self {
        self.mode = Mode::Mpc;
        self
    }

    /// Uses proxy mode for creating commitments.
    pub fn proxy(mut self) -> Self {
        self.mode = Mode::Proxy;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<VerifierConfig, VerifierConfigError> {
        let root_store = self
            .root_store
            .ok_or(ErrorRepr::MissingField { name: "root_store" })?;
        let mode = self.mode;

        Ok(VerifierConfig { root_store, mode })
    }
}

/// The mode of operation the verifier accepts.
///
/// Sets how the TLS transcript commitments can be created.
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Mode {
    /// Only accepts multi-party computation.
    #[default]
    Mpc,
    /// Only accepts proxy mode.
    Proxy,
}

impl PartialEq<TlsCommitProtocolConfig> for Mode {
    fn eq(&self, other: &TlsCommitProtocolConfig) -> bool {
        if matches!(self, Self::Mpc) && matches!(other, TlsCommitProtocolConfig::Mpc(_)) {
            return true;
        }
        if matches!(self, Self::Proxy) && matches!(other, TlsCommitProtocolConfig::Proxy(_)) {
            return true;
        }
        false
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Mpc => write!(f, "MPC mode"),
            Mode::Proxy => write!(f, "Proxy mode"),
        }
    }
}

/// Error for [`VerifierConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifierConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
}
