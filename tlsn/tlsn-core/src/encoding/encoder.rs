use mpz_circuits::types::ValueType;
use mpz_core::serialize::CanonicalSerialize;
use mpz_garble_core::ChaChaEncoder;

use crate::{
    transcript::{SliceIdx, SubsequenceIdx, RX_TRANSCRIPT_ID, TX_TRANSCRIPT_ID},
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
    /// Returns the encoding for the given slice of the transcript.
    ///
    /// # Arguments
    ///
    /// * `idx` - The index of the slice.
    /// * `data` - The data to encode.
    fn encode_slice(&self, idx: &SliceIdx, data: &[u8]) -> Vec<u8>;

    /// Returns the encoding for the given subsequence of the transcript.
    ///
    /// # Arguments
    ///
    /// * `seq` - The index of the subsequence.
    /// * `data` - The data to encode.
    fn encode_subsequence(&self, seq: &SubsequenceIdx, data: &[u8]) -> Vec<u8>;
}

impl Encoder for ChaChaEncoder {
    fn encode_slice(&self, idx: &SliceIdx, data: &[u8]) -> Vec<u8> {
        assert_eq!(
            idx.range.len(),
            data.len(),
            "range and data must have the same length"
        );

        let id = match idx.direction {
            Direction::Sent => TX_TRANSCRIPT_ID,
            Direction::Received => RX_TRANSCRIPT_ID,
        };

        idx.range
            .clone()
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
            encoding.extend(self.encode_slice(
                &SliceIdx {
                    direction: seq.direction,
                    range,
                },
                chunk,
            ));
        }
        encoding
    }
}
