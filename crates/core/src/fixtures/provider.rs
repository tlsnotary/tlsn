use std::ops::Range;

use crate::transcript::{
    encoding::{new_encoder, Encoder, EncoderSecret, EncodingProvider, EncodingProviderError},
    Direction, Transcript,
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
    fn provide_encoding(
        &self,
        direction: Direction,
        range: Range<usize>,
        dest: &mut Vec<u8>,
    ) -> Result<(), EncodingProviderError> {
        let transcript = match direction {
            Direction::Sent => &self.transcript.sent(),
            Direction::Received => &self.transcript.received(),
        };

        let data = transcript.get(range.clone()).ok_or(EncodingProviderError)?;
        self.encoder.encode_data(direction, range, data, dest);

        Ok(())
    }
}
