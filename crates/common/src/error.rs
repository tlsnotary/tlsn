//! Protocol errors.

use serde::{Deserialize, Serialize};

use crate::config::ProtocolConfigError;

/// An error sent by the peer.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[error("peer error: {0}")]
pub struct PeerError(#[from] Repr);

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
enum Repr {
    #[error("protocol configuration was rejected by the verifier, reason: {reason}")]
    Config { reason: String },
}

impl From<&ProtocolConfigError> for PeerError {
    fn from(value: &ProtocolConfigError) -> Self {
        PeerError(Repr::Config {
            reason: value.to_string(),
        })
    }
}
