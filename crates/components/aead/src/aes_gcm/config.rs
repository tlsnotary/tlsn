use derive_builder::Builder;

/// Protocol role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// Configuration for AES-GCM.
#[derive(Debug, Clone, Builder)]
pub struct AesGcmConfig {
    /// The id of this instance.
    #[builder(setter(into))]
    id: String,
    /// The protocol role.
    role: Role,
}

impl AesGcmConfig {
    /// Creates a new builder for the AES-GCM configuration.
    pub fn builder() -> AesGcmConfigBuilder {
        AesGcmConfigBuilder::default()
    }

    /// Returns the id of this instance.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the protocol role.
    pub fn role(&self) -> &Role {
        &self.role
    }
}
