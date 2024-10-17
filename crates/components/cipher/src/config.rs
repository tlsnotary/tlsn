//! Configuration for ciphers.

use derive_builder::Builder;

/// Configuration for the cipher.
#[derive(Debug, Clone, Builder)]
pub struct CipherConfig {
    /// The id of this instance.
    #[builder(setter(into))]
    id: String,
}

impl CipherConfig {
    /// Creates a new builder for the cipher configuration.
    pub fn builder() -> CipherConfigBuilder {
        CipherConfigBuilder::default()
    }

    /// Returns the id of this instance.
    pub fn id(&self) -> &str {
        &self.id
    }
}
