//! Adapted from tlsn/mpc/mpc-core, except [encode() in](ChaChaEncoder) was modified to encode 1 bit
//! at a time
use super::LabelSeed;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::ops::BitXor;

const DELTA_STREAM_ID: u64 = u64::MAX;
const PLAINTEXT_STREAM_ID: u64 = 1;

#[derive(Clone, Copy)]
pub struct Block(u128);

impl Block {
    #[inline]
    pub fn new(b: u128) -> Self {
        Self(b)
    }

    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    #[inline]
    pub fn set_lsb(&mut self) {
        self.0 |= 1;
    }

    #[inline]
    pub fn inner(&self) -> u128 {
        self.0
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

/// Global binary offset used by the Free-XOR technique to create wire label
/// pairs where W_1 = W_0 ^ Delta.
///
/// In accordance with the (p&p) permute-and-point technique, the LSB of delta is set to 1 so
/// the permute bit LSB(W_1) = LSB(W_0) ^ 1
#[derive(Clone, Copy)]
pub struct Delta(Block);

impl Delta {
    /// Creates new random Delta
    pub(crate) fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut block = Block::random(rng);
        block.set_lsb();
        Self(block)
    }

    /// Returns the inner block
    #[inline]
    pub(crate) fn into_inner(self) -> Block {
        self.0
    }
}

/// Encodes wires into labels using the ChaCha algorithm.
pub struct ChaChaEncoder {
    rng: ChaCha20Rng,
    delta: Delta,
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    pub fn new(seed: LabelSeed) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Stream id u64::MAX is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(DELTA_STREAM_ID);
        let delta = Delta::random(&mut rng);

        Self { rng, delta }
    }

    /// Encodes one bit of plaintext into two labels
    ///
    /// * `pos` - The position of a bit which needs to be encoded
    pub fn encode(&mut self, pos: usize) -> [Block; 2] {
        self.rng.set_stream(PLAINTEXT_STREAM_ID);

        // jump to the multiple-of-128 bit offset (128 bits is the size of one label)
        self.rng.set_word_pos((pos as u128) * 4);

        let zero_label = Block::random(&mut self.rng);

        [zero_label, zero_label ^ self.delta.into_inner()]
    }
}
