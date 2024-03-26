use std::ops::Range;

use mpz_garble_core::ChaChaEncoder;
use utils::range::RangeSet;

use crate::{
    encoding::{Encoder, EncodingProvider},
    transcript::SubsequenceIdx,
    Direction, Transcript,
};

/// A ChaCha encoding provider fixture.
pub struct ChaChaProvider {
    encoder: ChaChaEncoder,
    transcript_tx: Transcript,
    transcript_rx: Transcript,
}

impl ChaChaProvider {
    /// Creates a new ChaCha encoding provider.
    pub(crate) fn new(
        seed: [u8; 32],
        transcript_tx: Transcript,
        transcript_rx: Transcript,
    ) -> Self {
        Self {
            encoder: ChaChaEncoder::new(seed),
            transcript_tx,
            transcript_rx,
        }
    }
}

impl EncodingProvider for ChaChaProvider {
    fn provide_range(&self, range: Range<usize>, direction: Direction) -> Option<Vec<u8>> {
        let transcript = match direction {
            Direction::Sent => &self.transcript_tx,
            Direction::Received => &self.transcript_rx,
        };

        if range.end > transcript.len() {
            return None;
        }

        Some(
            self.encoder
                .encode(direction, range.clone(), &transcript.data()[range]),
        )
    }

    fn provide_ranges(&self, ranges: RangeSet<usize>, direction: Direction) -> Option<Vec<u8>> {
        let transcript = match direction {
            Direction::Sent => &self.transcript_tx,
            Direction::Received => &self.transcript_rx,
        };

        if ranges.max()? > transcript.len() {
            return None;
        }

        Some(self.encoder.encode_subsequence(
            &SubsequenceIdx {
                ranges: ranges.clone(),
                direction,
            },
            &transcript.get_bytes_in_ranges(&ranges),
        ))
    }
}
