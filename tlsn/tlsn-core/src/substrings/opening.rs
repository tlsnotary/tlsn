use crate::substrings::SubstringsOpeningError;
use mpz_core::{
    commit::{Decommitment, Nonce},
    hash::Hash,
};
use mpz_garble_core::{encoding_state::Full, EncodedValue};
use serde::{Deserialize, Serialize};

/// Opens a commitment to substrings of the transcript.
#[derive(Serialize, Deserialize, Clone)]
#[allow(missing_docs)]
pub enum SubstringsOpening {
    Blake3(Blake3Opening),
}

impl SubstringsOpening {
    /// Calculates the hash of the corresponding commitment
    pub fn hash(&self, encodings: &[EncodedValue<Full>]) -> Result<Hash, SubstringsOpeningError> {
        match self {
            SubstringsOpening::Blake3(opening) => opening.hash(encodings),
        }
    }

    /// Returns the transcript data corresponding to this opening
    pub fn into_data(self) -> Vec<u8> {
        match self {
            SubstringsOpening::Blake3(opening) => opening.into_data(),
        }
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

    /// Calculates the hash of the corresponding commitment
    pub fn hash(&self, encodings: &[EncodedValue<Full>]) -> Result<Hash, SubstringsOpeningError> {
        if encodings.len() != self.data.len() {
            return Err(SubstringsOpeningError::InvalidEncodingLength(
                encodings.len(),
                self.data.len(),
            ));
        }

        let encodings = encodings
            .iter()
            .zip(&self.data)
            .map(|(encoding, data)| encoding.select(*data).expect("encoding is for a u8"))
            .collect::<Vec<_>>();

        Ok(Decommitment::new_with_nonce(encodings, self.nonce).commit())
    }

    /// Returns the transcript data corresponding to this opening
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}
