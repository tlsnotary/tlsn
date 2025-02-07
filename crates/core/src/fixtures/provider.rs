use crate::transcript::{
    encoding::{new_encoder, Encoder, EncoderSecret, EncodingProvider},
    Direction, Idx, Transcript,
};

/// A encoding provider fixture.
pub struct FixtureEncodingProvider {
    encoder: Box<dyn Encoder>,
    transcript: Transcript,
}

impl FixtureEncodingProvider {
    /// Creates a new encoding provider fixture.
    pub(crate) fn new(secret: &EncoderSecret, transcript: Transcript) -> Self {
        Self {
            encoder: Box::new(new_encoder(secret)),
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
