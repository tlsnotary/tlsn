//! This module provides the [KeyExchangeConfig] for configuration of the key exchange instance

use super::role::Role;
use derive_builder::Builder;

/// A config used in the key exchange protocol
#[derive(Debug, Clone, Builder)]
pub struct KeyExchangeConfig<R> {
    pub(crate) id: String,
    pub(crate) role: R,
    #[builder(default = "u32::MAX")]
    pub(crate) encoder_default_stream_id: u32,
}

impl<R: Role> KeyExchangeConfig<R> {
    /// Get the id of this instance
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the role of this instance
    pub fn role(&self) -> &R {
        &self.role
    }
}
