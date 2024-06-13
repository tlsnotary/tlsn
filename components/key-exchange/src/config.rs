use derive_builder::Builder;

/// Role in the key exchange protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Leader.
    Leader,
    /// Follower.
    Follower,
}

/// A config used for [MpcKeyExchange](super::MpcKeyExchange).
#[derive(Debug, Clone, Builder)]
pub struct KeyExchangeConfig {
    /// Protocol role.
    role: Role,
}

impl KeyExchangeConfig {
    /// Creates a new builder for the key exchange configuration.
    pub fn builder() -> KeyExchangeConfigBuilder {
        KeyExchangeConfigBuilder::default()
    }

    /// Get the role of this instance.
    pub fn role(&self) -> &Role {
        &self.role
    }
}
