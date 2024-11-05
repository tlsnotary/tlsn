//! A convenience type for using AuthDecode with transcript data.
use core::ops::Range;
use getset::Getters;
use serde::{Deserialize, Serialize};

use authdecode_core::{
    backend::halo2::CHUNK_SIZE,
    encodings::{Encoding, EncodingProvider, EncodingProviderError, FullEncodings},
    id::{Id, IdCollection},
    SSP,
};
use mpz_circuits::types::ValueType;
use mpz_core::{utils::blake3, Block};
use mpz_garble_core::ChaChaEncoder;
use tlsn_core::transcript::{Direction, RX_TRANSCRIPT_ID, TX_TRANSCRIPT_ID};

#[derive(Clone, PartialEq, Serialize, Deserialize, Getters)]
/// Information about a subset of transcript data.
///
/// The data is treated as a big-endian bytestring with MSB0 bit ordering.
pub struct TranscriptData {
    /// The direction in which the data was transmitted.
    #[getset(get = "pub")]
    direction: Direction,
    /// The byterange in the transcript where the data is located.  
    #[getset(get = "pub")]
    range: Range<usize>,
}

impl TranscriptData {
    /// Creates a new `TranscriptData`.
    ///
    /// # Panics
    ///
    /// Panics if the range length exceeds the maximim allowed length.
    pub fn new(direction: Direction, range: &Range<usize>) -> Self {
        assert!(range.len() <= CHUNK_SIZE);

        Self {
            direction,
            range: range.clone(),
        }
    }
}

impl Default for TranscriptData {
    fn default() -> Self {
        Self {
            direction: Direction::Sent,
            range: Range::default(),
        }
    }
}

impl IdCollection for TranscriptData {
    fn drain_front(&mut self, count: usize) -> Self {
        assert!(count % 8 == 0);
        assert!(count <= CHUNK_SIZE * 8);
        // We will never need to drain since the collection spans a single chunk.
        self.clone()
    }

    fn id(&self, _index: usize) -> Id {
        unimplemented!()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.range.len() * 8
    }

    fn new_from_iter<I: IntoIterator<Item = Self>>(_iter: I) -> Self {
        unimplemented!()
    }
}

/// An encoder of a TLS transcript.
pub struct TranscriptEncoder {
    encoder: ChaChaEncoder,
}

impl TranscriptEncoder {
    /// Creates a new encoder from the `seed`.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed to create the encoder from.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            encoder: ChaChaEncoder::new(seed),
        }
    }

    /// Encodes a byte at the given position and direction in the transcript.
    fn encode_byte(&self, dir: Direction, pos: usize) -> Vec<[Encoding; 2]> {
        let id = match dir {
            Direction::Sent => TX_TRANSCRIPT_ID,
            Direction::Received => RX_TRANSCRIPT_ID,
        };

        let id_hash = blake3(format!("{}/{}", id, pos).as_bytes());
        let id = u64::from_be_bytes(id_hash[..8].try_into().unwrap());

        let mut encodings = <ChaChaEncoder as mpz_garble_core::Encoder>::encode_by_type(
            &self.encoder,
            id,
            &ValueType::U8,
        )
        .iter_blocks()
        .map(|blocks| {
            // Hash the encodings to break the correlation and truncate them.
            [
                Encoding::new(
                    blake3(&Block::to_bytes(blocks[0]))[0..SSP / 8]
                        .try_into()
                        .unwrap(),
                    false,
                ),
                Encoding::new(
                    blake3(&Block::to_bytes(blocks[1]))[0..SSP / 8]
                        .try_into()
                        .unwrap(),
                    true,
                ),
            ]
        })
        .collect::<Vec<_>>();
        // Reverse byte encodings to MSB0.
        encodings.reverse();
        encodings
    }
}

impl EncodingProvider<TranscriptData> for TranscriptEncoder {
    fn get_by_ids(
        &self,
        ids: &TranscriptData,
    ) -> Result<FullEncodings<TranscriptData>, EncodingProviderError> {
        let mut full_encoding = Vec::with_capacity(ids.range().len() * 8);

        for pos in ids.range().clone() {
            full_encoding.extend(self.encode_byte(*ids.direction(), pos));
        }

        Ok(FullEncodings::new(full_encoding, ids.clone()))
    }
}
