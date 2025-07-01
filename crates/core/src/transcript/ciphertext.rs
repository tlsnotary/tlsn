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
    ciphertext: Vec<u8>,
    key: TypedHash,
}

/// Proof for a [`Ciphertext`] commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// Blinder for the hash.
    pub blinder: Blinder,
    /// Direction of the plaintext.
    pub direction: Direction,
    /// The corresponding plaintext.
    pub plaintext: Vec<u8>,
    /// The session key.
    pub key: SessionKey,
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
        &self,
        provider: &CryptoProvider,
        commitments: &HashSet<&Ciphertext>,
    ) -> Result<Idx, PlaintextProofError> {
        let hasher = provider.hash.get(&self.alg)?;

        let expected = Ciphertext {
            direction: self.direction,
            ciphertext: todo!(),
            key: self.key.hash(hasher, &self.blinder),
        };

        todo!()
    }
}

/// TLS session key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionKey {
    direction: Direction,
    key: Vec<u8>,
}

impl SessionKey {
    /// Hashes the session key with a blinder.
    ///
    /// By convention, session key is hashed as `H(msg | blinder)`.
    pub fn hash(&self, hasher: &dyn HashAlgorithm, blinder: &Blinder) -> TypedHash {
        TypedHash {
            alg: hasher.id(),
            value: hasher.hash_prefixed(&self.key, blinder.as_bytes()),
        }
    }
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
