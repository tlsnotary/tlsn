use mpz_garble_core::ChaChaEncoder;

use crate::transcript::{
    encoding::{Encoder, EncodingProvider},
    Direction, Idx, Transcript,
};

/// A ChaCha encoding provider fixture.
pub struct ChaChaProvider {
    encoder: ChaChaEncoder,
    transcript: Transcript,
}

impl ChaChaProvider {
    /// Creates a new ChaCha encoding provider.
    pub(crate) fn new(seed: [u8; 32], transcript: Transcript) -> Self {
        Self {
            encoder: ChaChaEncoder::new(seed),
            transcript,
        }
    }
}

impl EncodingProvider for ChaChaProvider {
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>> {
        let seq = self.transcript.get(direction, idx)?;
        Some(self.encoder.encode_subsequence(direction, &seq))
    }
}
