use std::ops::Range;

use crate::transcript::Direction;
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
    /// Writes the zero encoding for the given range of the transcript into the
    /// destination buffer.
    fn encode_range(&self, direction: Direction, range: Range<usize>, dest: &mut Vec<u8>);

    /// Writes the encoding for the given data into the destination buffer.
    fn encode_data(
        &self,
        direction: Direction,
        range: Range<usize>,
        data: &[u8],
        dest: &mut Vec<u8>,
    );
}

impl Encoder for ChaChaEncoder {
    fn encode_range(&self, direction: Direction, range: Range<usize>, dest: &mut Vec<u8>) {
        // ChaCha encoder works with 32-bit words. Each encoded bit is 128 bits long.
        const WORDS_PER_BYTE: u128 = 8 * 128 / 32;

        let stream_id: u64 = match direction {
            Direction::Sent => 0,
            Direction::Received => 1,
        };

        let mut prg = self.new_prg(stream_id);
        let len = range.len() * BYTE_ENCODING_SIZE;
        let pos = dest.len();

        // Write 0s to the destination buffer.
        dest.resize(pos + len, 0);

        // Fill the destination buffer with the PRG.
        prg.set_word_pos(range.start as u128 * WORDS_PER_BYTE);
        prg.fill_bytes(&mut dest[pos..pos + len]);
    }

    fn encode_data(
        &self,
        direction: Direction,
        range: Range<usize>,
        data: &[u8],
        dest: &mut Vec<u8>,
    ) {
        const ZERO: [u8; 16] = [0; BIT_ENCODING_SIZE];

        let pos = dest.len();

        // Write the zero encoding for the given range.
        self.encode_range(direction, range, dest);
        let dest = &mut dest[pos..];

        for (pos, bit) in data.iter_lsb0().enumerate() {
            // Add the delta to the encoding whenever the encoded bit is 1,
            // otherwise add a zero.
            let summand = if bit { &self.delta } else { &ZERO };
            dest[pos * BIT_ENCODING_SIZE..(pos + 1) * BIT_ENCODING_SIZE]
                .iter_mut()
                .zip(summand)
                .for_each(|(a, b)| *a ^= *b);
        }
    }
}
