//! This module provides the [KeyExchangeConfig] for configuration of the key exchange instance

use derive_builder::Builder;

/// Role in the key exchange protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// A config used in the key exchange protocol
#[derive(Debug, Clone, Builder)]
pub struct KeyExchangeConfig {
    /// The id of this instance
    id: String,
    /// Protocol role
    role: Role,
}

impl KeyExchangeConfig {
    /// Get the id of this instance
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the role of this instance
    pub fn role(&self) -> &Role {
        &self.role
    }
}
