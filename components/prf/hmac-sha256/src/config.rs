use derive_builder::Builder;

/// Role of this party in the PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The leader provides the private inputs to the PRF.
    Leader,
    /// The follower is blind to the inputs to the PRF.
    Follower,
}

/// Configuration for the PRF.
#[derive(Debug, Builder)]
pub struct PrfConfig {
    /// The role of this party in the PRF.
    pub(crate) role: Role,
}

impl PrfConfig {
    /// Creates a new builder.
    pub fn builder() -> PrfConfigBuilder {
        PrfConfigBuilder::default()
    }
}
