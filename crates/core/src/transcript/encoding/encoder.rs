use crate::transcript::{Direction, Subsequence};
use itybity::ToBits;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Deserialize, Serialize};

/// Secret used by an encoder to generate encodings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderSecret {
    seed: Vec<u8>,
    delta: Vec<u8>,
}

opaque_debug::implement!(EncoderSecret);

impl EncoderSecret {
    /// Creates a new secret.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    /// * `delta` - Delta for deriving the one-encodings.
    pub fn new(seed: [u8; 32], delta: [u8; 16]) -> Self {
        Self {
            seed: seed.to_vec(),
            delta: delta.to_vec(),
        }
    }

    /// Returns the seed.
    pub fn to_seed(&self) -> [u8; 32] {
        self.seed
            .clone()
            .try_into()
            .expect("Seed should be 32 bytes")
    }

    /// Returns the delta.
    pub fn to_delta(&self) -> [u8; 16] {
        self.delta
            .clone()
            .try_into()
            .expect("Delta should be 16 bytes")
    }
}

pub(crate) fn new_encoder(secret: &EncoderSecret) -> impl Encoder {
    ChaChaEncoder::new(secret)
}

pub(crate) struct ChaChaEncoder {
    seed: [u8; 32],
    delta: u128,
}

impl ChaChaEncoder {
    pub(crate) fn new(secret: &EncoderSecret) -> Self {
        let seed = secret.to_seed();
        let delta = u128::from_le_bytes(secret.to_delta());

        Self { seed, delta }
    }

    pub(crate) fn new_prg(&self, stream_id: u64) -> ChaCha12Rng {
        let mut prg = ChaCha12Rng::from_seed(self.seed);
        prg.set_stream(stream_id);
        prg.set_word_pos(0);
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
        // ChaCha20 encoder works with 32-bit words. Each encoded bit is 128 bits long.
        const WORDS_PER_BYTE: u128 = 8 * 128 / 32;

        let stream_id: u64 = match direction {
            Direction::Sent => 0,
            Direction::Received => 1,
        };

        let mut prg = self.new_prg(stream_id);
        let mut encodings: Vec<u8> = Vec::with_capacity(seq.len() * 128);

        for (id, &byte) in seq.index().iter().zip(seq.data()) {
            prg.set_word_pos(id as u128 * WORDS_PER_BYTE);
            let bits = byte.iter_lsb0();

            for bit in bits {
                let enc = prg.gen::<u128>() ^ (bit as u128 * self.delta);
                encodings.extend_from_slice(&enc.to_le_bytes());
            }
        }

        encodings
    }
}
