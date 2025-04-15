use crate::transcript::{Direction, Idx, Subsequence};
use itybity::ToBits;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Deserialize, Serialize};

/// The size of the encoding for 1 bit, in bytes.
const BIT_ENCODING_SIZE: usize = 16;
/// The size of the encoding for 1 byte, in bytes.
const BYTE_ENCODING_SIZE: usize = 128;

/// Secret used by an encoder to generate encodings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderSecret {
    seed: [u8; 32],
    delta: [u8; BIT_ENCODING_SIZE],
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
        Self { seed, delta }
    }

    /// Returns the seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Returns the delta.
    pub fn delta(&self) -> &[u8; 16] {
        &self.delta
    }
}

/// Creates a new encoder.
pub fn new_encoder(secret: &EncoderSecret) -> impl Encoder {
    ChaChaEncoder::new(secret)
}

pub(crate) struct ChaChaEncoder {
    seed: [u8; 32],
    delta: [u8; 16],
}

impl ChaChaEncoder {
    pub(crate) fn new(secret: &EncoderSecret) -> Self {
        let seed = *secret.seed();
        let delta = *secret.delta();

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
pub trait Encoder {
    /// Returns the zero encoding for the given index.
    fn encode_idx(&self, direction: Direction, idx: &Idx) -> Vec<u8>;

    /// Returns the encoding for the given subsequence of the transcript.
    ///
    /// # Arguments
    ///
    /// * `seq` - The subsequence to encode.
    fn encode_subsequence(&self, direction: Direction, seq: &Subsequence) -> Vec<u8>;
}

impl Encoder for ChaChaEncoder {
    fn encode_idx(&self, direction: Direction, idx: &Idx) -> Vec<u8> {
        // ChaCha encoder works with 32-bit words. Each encoded bit is 128 bits long.
        const WORDS_PER_BYTE: u128 = 8 * 128 / 32;

        let stream_id: u64 = match direction {
            Direction::Sent => 0,
            Direction::Received => 1,
        };

        let mut prg = self.new_prg(stream_id);
        let mut encoding: Vec<u8> = vec![0u8; idx.len() * BYTE_ENCODING_SIZE];

        let mut pos = 0;
        for range in idx.iter_ranges() {
            let len = range.len() * BYTE_ENCODING_SIZE;
            prg.set_word_pos(range.start as u128 * WORDS_PER_BYTE);
            prg.fill_bytes(&mut encoding[pos..pos + len]);
            pos += len;
        }

        encoding
    }

    fn encode_subsequence(&self, direction: Direction, seq: &Subsequence) -> Vec<u8> {
        const ZERO: [u8; 16] = [0; BIT_ENCODING_SIZE];
        let mut encoding = self.encode_idx(direction, seq.index());
        for (byte_idx, &byte) in seq.data().iter().enumerate() {
            let start = byte_idx * BYTE_ENCODING_SIZE;
            for (bit_idx, bit) in byte.iter_lsb0().enumerate() {
                let pos = start + (bit_idx * BIT_ENCODING_SIZE);
                let delta = if bit { &self.delta } else { &ZERO };

                encoding[pos..pos + BIT_ENCODING_SIZE]
                    .iter_mut()
                    .zip(delta)
                    .for_each(|(a, b)| *a ^= *b);
            }
        }

        encoding
    }
}
