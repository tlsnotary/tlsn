use crate::transcript::{
    encoding::{new_encoder, Encoder, EncodingProvider},
    Direction, Idx, Transcript,
};

/// A encoding provider fixture.
pub struct FixtureEncodingProvider {
    encoder: Box<dyn Encoder>,
    transcript: Transcript,
}

impl FixtureEncodingProvider {
    /// Creates a new encoding provider fixture.
    pub(crate) fn new(seed: [u8; 32], delta: [u8; 16], transcript: Transcript) -> Self {
        Self {
            encoder: Box::new(new_encoder(seed, delta)),
            transcript,
        }
    }
}

impl EncodingProvider for FixtureEncodingProvider {
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>> {
        let seq = self.transcript.get(direction, idx)?;
        Some(self.encoder.encode_subsequence(direction, &seq))
    }
}
