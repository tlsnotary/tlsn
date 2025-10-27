//! Prover configuration.

use serde::{Deserialize, Serialize};

/// Prover configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {}

impl ProverConfig {
    /// Creates a new builder.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }
}

/// Builder for [`ProverConfig`].
#[derive(Debug, Default)]
pub struct ProverConfigBuilder {}

impl ProverConfigBuilder {
    /// Builds the configuration.
    pub fn build(self) -> Result<ProverConfig, ProverConfigError> {
        Ok(ProverConfig {})
    }
}

/// Error for [`ProverConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProverConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {}
