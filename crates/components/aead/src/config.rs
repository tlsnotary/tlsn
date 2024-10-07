use derive_builder::Builder;

/// Protocol role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// Configuration for MPC-AEAD.
#[derive(Debug, Clone, Builder)]
pub struct MpcAeadConfig {
    /// The id of this instance.
    #[builder(setter(into))]
    id: String,
    /// The protocol role.
    role: Role,
}

impl MpcAeadConfig {
    /// Creates a new builder for the MPC-AEAD configuration.
    pub fn builder() -> MpcAeadConfigBuilder {
        MpcAeadConfigBuilder::default()
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
