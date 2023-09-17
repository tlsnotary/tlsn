use crate::{commitment::Commitment, substrings::opening::Blake3Opening};
use mpz_core::{
    commit::{HashCommit, Nonce},
    hash::Hash,
};
use mpz_garble_core::{encoding_state, EncodedValue};
use serde::{Deserialize, Serialize};

use super::opening::SubstringsOpening;

/// A commitment to one or multiple substrings of a [`Transcript`](crate::Transcript).
#[derive(Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub enum SubstringsCommitment {
    /// A Blake3 commitment to the encodings of the substrings
    Blake3(Blake3SubstringsCommitment),
}

opaque_debug::implement!(SubstringsCommitment);

impl SubstringsCommitment {
    /// Opens this commitment
    pub fn open(&self, data: Vec<u8>) -> SubstringsOpening {
        match self {
            SubstringsCommitment::Blake3(com) => SubstringsOpening::Blake3(com.open(data)),
        }
    }

    /// Returns the kind of this commitment
    pub fn kind(&self) -> SubstringsCommitmentKind {
        match self {
            SubstringsCommitment::Blake3(_) => SubstringsCommitmentKind::Blake3,
        }
    }
}

/// The kind of a [`SubstringsCommitment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SubstringsCommitmentKind {
    /// A Blake3 commitment to the encodings of the substrings
    Blake3,
}

/// A Blake3 commitment to the encodings of the substrings of a [`Transcript`](crate::Transcript).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Blake3SubstringsCommitment {
    hash: Hash,
    nonce: Nonce,
}

opaque_debug::implement!(Blake3SubstringsCommitment);

impl Blake3SubstringsCommitment {
    /// Creates a new Blake3 commitment
    pub fn new(encodings: &[EncodedValue<encoding_state::Active>]) -> Self {
        let (decommitment, hash) = encodings.hash_commit();

        Self {
            hash,
            nonce: *decommitment.nonce(),
        }
    }

    /// Returns the hash of this commitment
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Returns the nonce of this commitment
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Opens this commitment
    pub fn open(&self, data: Vec<u8>) -> Blake3Opening {
        Blake3Opening::new(data, self.nonce)
    }
}

impl From<Blake3SubstringsCommitment> for SubstringsCommitment {
    fn from(value: Blake3SubstringsCommitment) -> Self {
        Self::Blake3(value)
    }
}

impl From<Blake3SubstringsCommitment> for Commitment {
    fn from(value: Blake3SubstringsCommitment) -> Self {
        Self::Substrings(value.into())
    }
}
