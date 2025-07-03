//! Ciphertext commitments and proof.

use crate::{
    hash::{Blinder, HashAlgId, HashProviderError, TypedHash},
    transcript::{Direction, Idx, Transcript},
    CryptoProvider,
};
use serde::{Deserialize, Serialize};

/// Ciphertext commitment.
///
/// Also contains a commitment to the client or sever write key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CiphertextCommitment {
    idx: Idx,
    ciphertext: Vec<u8>,
    explicit_nonces: Vec<u8>,
    counters: Vec<u8>,
    key_iv_hash: TypedHash,
}

/// Proof for a [`Ciphertext`] commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// The corresponding indices.
    pub idx: Idx,
    /// Secret of the session.
    pub secret: SessionSecret,
}

impl PlaintextProof {
    /// Creates a new proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - The TLS transcript.
    /// * `secret` - The session secret.
    pub fn new(transcript: &Transcript, secret: SessionSecret) -> Self {
        let plaintext = transcript.received.clone();
        let len = transcript.len_of_direction(Direction::Received);
        let idx = Idx::new(0..len);

        PlaintextProof {
            plaintext,
            idx,
            secret,
        }
    }

    /// Verifies the plaintext proof.
    ///
    /// Returns the authed indices.
    ///
    /// # Arguments
    ///
    /// * `provider` - Provider for the hash algorithm used.
    /// * `commitments` - Commitments to verify with this proof.
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        commitment: &CiphertextCommitment,
    ) -> Result<Idx, PlaintextProofError> {
        // TODO: Reconstruct ciphertext from plaintext. Need iv, explicit_nonce, counters...
        let expected = CiphertextCommitment {
            idx: self.idx,
            ciphertext: todo!(),
            explicit_nonces: todo!(),
            counters: todo!(),
            key_iv_hash: todo!(),
        };

        if &expected != commitment {
            return Err(PlaintextProofError::new(
                ErrorKind::Proof,
                "Proof does not match any commitment",
            ));
        }
        let idx = commitment.idx.clone();

        Ok(idx)
    }
}

/// TLS session secret.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SessionSecret {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// The session key.
    pub key: SessionKey,
    /// Blinder for the key.
    pub blinder: Blinder,
}

opaque_debug::implement!(SessionSecret);

/// The server write key and iv.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SessionKey {
    /// The key.
    pub key: [u8; 16],
    /// The iv.
    pub iv: [u8; 4],
}

opaque_debug::implement!(SessionKey);

/// Error for [`PlaintextProof`].
#[derive(Debug, thiserror::Error)]
pub struct PlaintextProofError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PlaintextProofError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Provider,
    Proof,
}

impl std::fmt::Display for PlaintextProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("encoding proof error: ")?;

        match self.kind {
            ErrorKind::Provider => f.write_str("provider error")?,
            ErrorKind::Proof => f.write_str("proof error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<HashProviderError> for PlaintextProofError {
    fn from(error: HashProviderError) -> Self {
        Self::new(ErrorKind::Provider, error)
    }
}
