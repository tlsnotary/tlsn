use serde::{Deserialize, Serialize};

use p256::ecdsa::{signature::Verifier, VerifyingKey};

/// A Notary public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum NotaryPublicKey {
    /// A NIST P-256 public key.
    P256(p256::PublicKey),
}

impl From<p256::PublicKey> for NotaryPublicKey {
    fn from(key: p256::PublicKey) -> Self {
        Self::P256(key)
    }
}

/// An error occurred while verifying a signature.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureVerifyError(String);

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

    /// Verifies the signature.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to verify.
    /// * `notary_public_key` - The public key of the notary.
    pub fn verify(
        &self,
        msg: &[u8],
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SignatureVerifyError> {
        match (self, notary_public_key.into()) {
            (Self::P256(sig), NotaryPublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg, sig)
                .map_err(|e| SignatureVerifyError(e.to_string())),
        }
    }
}
