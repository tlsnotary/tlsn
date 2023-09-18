use serde::{Deserialize, Serialize};

/// A Notary signature.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum Signature {
    /// A secp256r1 signature.
    P256(p256::ecdsa::Signature),
}

impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

impl Signature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sig) => sig.to_vec(),
        }
    }
}
