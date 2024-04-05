use mpz_garble_core::ChaChaEncoder;

use crate::{
    encoding::{Encoder, EncodingProvider},
    transcript::{Subsequence, SubsequenceIdx},
    Transcript,
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
    fn provide_subsequence(&self, idx: &SubsequenceIdx) -> Option<Vec<u8>> {
        let data = self.transcript.get_subsequence(idx)?;
        let encoding = self.encoder.encode_subsequence(
            &Subsequence::new(idx.clone(), data).expect("data is same length as index"),
        );
        Some(encoding)
    }
}
