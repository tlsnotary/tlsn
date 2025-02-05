use itybity::ToBits;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::transcript::{Direction, Subsequence};

pub(crate) fn new_encoder(seed: [u8; 32], delta: [u8; 16]) -> impl Encoder {
    ChaChaEncoder::new(seed, delta)
}

pub struct ChaChaEncoder {
    seed: [u8; 32],
    delta: [u8; 16],
}

impl ChaChaEncoder {
    pub fn new(seed: [u8; 32], delta: [u8; 16]) -> Self {
        Self { seed, delta }
    }

    pub fn prg(&self, id: u64) -> ChaCha12Rng {
        let mut prg = ChaCha12Rng::from_seed(self.seed);
        prg.set_word_pos(0);
        prg.set_stream(id);
        prg
    }
}

/// A transcript encoder.
///
/// This is an internal implementation detail that should not be exposed to the
/// public API.
pub(crate) trait Encoder {
    /// Returns the encoding for the given subsequence of the transcript.
    ///
    /// # Arguments
    ///
    /// * `seq` - The subsequence to encode.
    fn encode_subsequence(&self, direction: Direction, seq: &Subsequence) -> Vec<u8>;
}

impl Encoder for ChaChaEncoder {
    fn encode_subsequence(&self, direction: Direction, seq: &Subsequence) -> Vec<u8> {
        let end = seq.index().end() as u64;
        assert!(end < u64::MAX >> 1, "Index too big to encode");

        let mask: u64 = match direction {
            Direction::Sent => 0,
            Direction::Received => 1 << 63,
        };

        let delta = u128::from_le_bytes(self.delta);
        let mut encodings: Vec<u8> = Vec::with_capacity(seq.len() * 128);

        for (id, &byte) in seq.index().iter().zip(seq.data()) {
            let mut prg = self.prg(id as u64 | mask);
            let bits = byte.iter_lsb0();

            for bit in bits {
                let enc = prg.gen::<u128>() + bit as u128 * delta;
                encodings.extend_from_slice(&enc.to_le_bytes());
            }
        }

        encodings
    }
}
