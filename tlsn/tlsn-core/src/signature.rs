//! A module for different signatures

use p256;
use serde::{Deserialize, Serialize};

/// Unifies different signature types
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Signature {
    P256(p256::ecdsa::Signature),
}

impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

impl Signature {
    /// Returns the signature as a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sig) => sig.to_vec(),
        }
    }
}
