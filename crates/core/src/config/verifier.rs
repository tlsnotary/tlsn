//! Verifier configuration.

use serde::{Deserialize, Serialize};

use crate::webpki::RootCertStore;

/// Verifier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    root_store: RootCertStore,
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
}

/// Builder for [`VerifierConfig`].
#[derive(Debug, Default)]
pub struct VerifierConfigBuilder {
    root_store: Option<RootCertStore>,
}

impl VerifierConfigBuilder {
    /// Sets the root certificate store.
    pub fn root_store(mut self, root_store: RootCertStore) -> Self {
        self.root_store = Some(root_store);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<VerifierConfig, VerifierConfigError> {
        let root_store = self
            .root_store
            .ok_or(ErrorRepr::MissingField { name: "root_store" })?;
        Ok(VerifierConfig { root_store })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webpki::RootCertStore;

    #[test]
    fn test_build_success() {
        let root_store = RootCertStore::empty();
        let config = VerifierConfig::builder()
            .root_store(root_store)
            .build()
            .unwrap();

        assert!(config.root_store().roots.is_empty());
    }

    #[test]
    fn test_build_missing_root_store() {
        let err = VerifierConfig::builder().build();
        assert!(err.is_err());
    }
}
