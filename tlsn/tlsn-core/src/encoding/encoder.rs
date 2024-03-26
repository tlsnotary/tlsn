use std::ops::Range;

use mpz_circuits::types::ValueType;
use mpz_core::serialize::CanonicalSerialize;
use mpz_garble_core::ChaChaEncoder;

use crate::{
    transcript::{SubsequenceIdx, RX_TRANSCRIPT_ID, TX_TRANSCRIPT_ID},
    Direction,
};

pub(crate) fn new_encoder(seed: [u8; 32]) -> impl Encoder {
    ChaChaEncoder::new(seed)
}

/// A transcript encoder.
///
/// This is an internal implementation detail that should not be exposed to the
/// public API.
pub(crate) trait Encoder {
    /// Returns the encoding for the given range of the transcript.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    /// * `range` - The range of the transcript.
    /// * `data` - The data to encode.
    fn encode(&self, direction: Direction, range: Range<usize>, data: &[u8]) -> Vec<u8>;

    /// Returns the encoding for the given subsequence of the transcript.
    ///
    /// # Arguments
    ///
    /// * `seq` - The subsequence of the transcript.
    /// * `data` - The data to encode.
    fn encode_subsequence(&self, seq: &SubsequenceIdx, data: &[u8]) -> Vec<u8>;
}

impl Encoder for ChaChaEncoder {
    fn encode(&self, direction: Direction, range: Range<usize>, data: &[u8]) -> Vec<u8> {
        assert_eq!(
            range.len(),
            data.len(),
            "range and data must have the same length"
        );

        let id = match direction {
            Direction::Sent => TX_TRANSCRIPT_ID,
            Direction::Received => RX_TRANSCRIPT_ID,
        };

        range
            .zip(data)
            .map(|(idx, byte)| {
                let id_hash = mpz_core::utils::blake3(format!("{}/{}", id, idx).as_bytes());
                let id = u64::from_be_bytes(id_hash[..8].try_into().unwrap());
                <ChaChaEncoder as mpz_garble_core::Encoder>::encode_by_type(
                    self,
                    id,
                    &ValueType::U8,
                )
                .select(*byte)
                .expect("encoding is a byte encoding")
                .to_bytes()
            })
            .flatten()
            .collect()
    }

    fn encode_subsequence(&self, seq: &SubsequenceIdx, mut data: &[u8]) -> Vec<u8> {
        assert_eq!(
            seq.ranges.len(),
            data.len(),
            "ranges and data must have the same length"
        );
        let mut encoding = Vec::with_capacity(data.len() * 16);
        for range in seq.ranges.iter_ranges() {
            let (chunk, rest) = data.split_at(range.len());
            data = rest;
            encoding.extend(self.encode(seq.direction, range, chunk));
        }
        encoding
    }
}
