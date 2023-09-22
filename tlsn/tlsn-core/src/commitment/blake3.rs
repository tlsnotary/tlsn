use crate::commitment::{Commitment, CommitmentOpening};
use mpz_core::{
    commit::{Decommitment, HashCommit, Nonce},
    hash::Hash,
};
use mpz_garble_core::{encoding_state, encoding_state::Full, EncodedValue};
use serde::{Deserialize, Serialize};

/// A Blake3 commitment to the encodings of the substrings of a [`Transcript`](crate::Transcript).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Blake3Commitment {
    hash: Hash,
    nonce: Nonce,
}

opaque_debug::implement!(Blake3Commitment);

impl Blake3Commitment {
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

impl From<Blake3Commitment> for Commitment {
    fn from(value: Blake3Commitment) -> Self {
        Self::Blake3(value)
    }
}

/// A substring opening using Blake3
#[derive(Serialize, Deserialize, Clone)]
pub struct Blake3Opening {
    data: Vec<u8>,
    nonce: Nonce,
}

impl Blake3Opening {
    pub(crate) fn new(data: Vec<u8>, nonce: Nonce) -> Self {
        Self { data, nonce }
    }

    /// Recovers the expected commitment from this opening.
    ///
    /// # Panics
    ///
    /// - If the number of encodings does not match the number of bytes in the opening.
    /// - If an encoding is not for a u8.
    pub fn recover(&self, encodings: &[EncodedValue<Full>]) -> Blake3Commitment {
        assert_eq!(
            encodings.len(),
            self.data.len(),
            "encodings and data must have the same length"
        );

        let encodings = encodings
            .iter()
            .zip(&self.data)
            .map(|(encoding, data)| encoding.select(*data).expect("encoding is for a u8"))
            .collect::<Vec<_>>();

        let hash = Decommitment::new_with_nonce(encodings, self.nonce).commit();

        Blake3Commitment {
            hash,
            nonce: self.nonce,
        }
    }

    /// Returns the transcript data corresponding to this opening
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the transcript data corresponding to this opening
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl From<Blake3Opening> for CommitmentOpening {
    fn from(value: Blake3Opening) -> Self {
        Self::Blake3(value)
    }
}
