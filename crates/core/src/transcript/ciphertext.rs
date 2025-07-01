//! Ciphertext commitments and proof.

use std::collections::HashSet;

use crate::{
    hash::{Blinder, HashAlgId, HashAlgorithm, HashProviderError, TypedHash},
    transcript::{Direction, Idx},
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
    //  TODO: should we use Merkle tree here to reduce commitment size?
    ciphertext: Vec<u8>,
    explicit_nonces: Vec<u8>,
    counters: Vec<u8>,
    key: TypedHash,
    iv: TypedHash,
}

/// Proof for a [`Ciphertext`] commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// Direction of the plaintext.
    pub direction: Direction,
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// The corresponding indices.
    pub idx: Idx,
    /// Secret of the session.
    pub secret: SessionSecret,
}

impl PlaintextProof {
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
        let hasher = provider.hash.get(&self.alg)?;

        // TODO: Reconstruct ciphertext from plaintext. Need iv, explicit_nonce, counters...
        let expected = Ciphertext {
            direction: self.direction,
            idx: self.idx,
            ciphertext: todo!(),
            explicit_nonces: todo!(),
            counters: todo!(),
            key: self.secret.hash_key(hasher),
            iv: self.secret.hash_iv(hasher),
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
    pub fn hash_key(&self, hasher: &dyn HashAlgorithm) -> TypedHash {
        TypedHash {
            alg: hasher.id(),
            value: hasher.hash_prefixed(&self.key, self.key_blinder.as_bytes()),
        }
    }

    /// Hashes the session iv with a blinder.
    ///
    /// By convention, session iv is hashed as `H(iv | blinder)`.
    pub fn hash_iv(&self, hasher: &dyn HashAlgorithm) -> TypedHash {
        TypedHash {
            alg: hasher.id(),
            value: hasher.hash_prefixed(&self.iv, self.iv_blinder.as_bytes()),
        }
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
