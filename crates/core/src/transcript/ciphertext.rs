//! Ciphertext commitments and proof.

use std::collections::HashSet;

use crate::{
    hash::{Blinder, HashAlgId, HashAlgorithm, HashProviderError, TypedHash},
    transcript::{Direction, Idx, Transcript},
    CryptoProvider,
};
use serde::{Deserialize, Serialize};

/// Ciphertext commitment.
///
/// Also contains a commitment to the client or sever write key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext {
    direction: Direction,
    idx: Idx,
    ciphertext: Vec<u8>,
    explicit_nonces: Vec<u8>,
    counters: Vec<u8>,
    key: TypedHash,
    iv: TypedHash,
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
        let direction = secret.direction;

        let plaintext = match direction {
            Direction::Sent => transcript.sent.clone(),
            Direction::Received => transcript.received.clone(),
        };

        let len = transcript.len_of_direction(direction);
        let idx = Idx::new(0..len);

        PlaintextProof {
            plaintext,
            idx,
            secret,
        }
    }

    /// Returns the direction.
    pub fn direction(&self) -> Direction {
        self.secret.direction
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
        commitments: &HashSet<&Ciphertext>,
    ) -> Result<Idx, PlaintextProofError> {
        // TODO: Reconstruct ciphertext from plaintext. Need iv, explicit_nonce, counters...
        let expected = Ciphertext {
            direction: self.secret.direction,
            idx: self.idx,
            ciphertext: todo!(),
            explicit_nonces: todo!(),
            counters: todo!(),
            key: self.secret.hash_key(provider)?,
            iv: self.secret.hash_iv(provider)?,
        };

        commitments
            .get(&expected)
            .ok_or_else(|| {
                PlaintextProofError::new(ErrorKind::Proof, "Proof does not match any commitment")
            })
            .map(|&commit| commit.idx.clone())
    }
}

/// TLS session key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSecret {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// Direction of the session key (cwk or swk).
    pub direction: Direction,
    /// Session key.
    pub key: Vec<u8>,
    /// Blinder for the session key.
    pub key_blinder: Blinder,
    /// Iv.
    pub iv: Vec<u8>,
    /// Blinder for the iv.
    pub iv_blinder: Blinder,
}

impl SessionSecret {
    /// Hashes the session key with a blinder.
    ///
    /// By convention, session key is hashed as `H(key | blinder)`.
    pub fn hash_key(&self, provider: &CryptoProvider) -> Result<TypedHash, PlaintextProofError> {
        let hasher = provider.hash.get(&self.alg)?;

        let hash = TypedHash {
            alg: hasher.id(),
            value: hasher.hash_prefixed(&self.key, self.key_blinder.as_bytes()),
        };

        Ok(hash)
    }

    /// Hashes the session iv with a blinder.
    ///
    /// By convention, session iv is hashed as `H(iv | blinder)`.
    pub fn hash_iv(&self, provider: &CryptoProvider) -> Result<TypedHash, PlaintextProofError> {
        let hasher = provider.hash.get(&self.alg)?;

        let hash = TypedHash {
            alg: hasher.id(),
            value: hasher.hash_prefixed(&self.iv, self.iv_blinder.as_bytes()),
        };

        Ok(hash)
    }
}

opaque_debug::implement!(SessionSecret);

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
