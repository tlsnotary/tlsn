//! Contains different commitment types

use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};

use crate::SubstringsCommitment;

/// A commitment id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitmentId(u32);

impl CommitmentId {
    /// Creates a new commitment id
    pub(crate) fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the inner value
    pub(crate) fn into_inner(self) -> u32 {
        self.0
    }
}

/// Unifies different commitment types
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub enum Commitment {
    Blake3(Blake3),
}

impl From<Blake3> for Commitment {
    fn from(c: Blake3) -> Self {
        Self::Blake3(c)
    }
}

/// A blake3 digest of the encoding of the plaintext
#[derive(Serialize, Deserialize, Clone)]
pub struct Blake3 {
    /// A salted hash of the encoding of the plaintext
    encoding_hash: Hash,
}

impl Blake3 {
    /// Creates a new Blake3 commitment
    pub fn new(encoding_hash: Hash) -> Self {
        Self { encoding_hash }
    }

    /// Returns reference to inner encoding hash
    pub fn encoding_hash(&self) -> &Hash {
        &self.encoding_hash
    }
}

/// A commitment to some bytes in a transcript
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptCommitment {
    /// A commitment to the encodings of substrings.
    Substrings(SubstringsCommitment),
}
