//! This module implements the extension field GF(2^128)

use super::Field;
use mpc_core::{Block, BlockSerialize};
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, Mul, Neg};
use utils::bits::{FromBits, ToBits};

/// A type for holding field elements of Gf(2^128)
///
/// Uses internally an  LSB0 encoding
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct Gf2_128(pub(crate) u128);

impl Gf2_128 {
    /// Creates a new field element from a u128,
    /// mapping the integer to the corresponding polynomial
    ///
    /// For example, 3u128 is mapped to the polynomial `1 + x^2`
    pub fn new(input: u128) -> Self {
        Gf2_128(input.reverse_bits())
    }

    /// Creates a new field element from a block.
    pub fn new_from_block(block: Block) -> Self {
        Gf2_128(block.inner())
    }

    /// Returns the element as a block
    pub fn to_block(&self) -> Block {
        Block::new(self.0)
    }
}

impl From<Gf2_128> for Block {
    fn from(value: Gf2_128) -> Self {
        Block::new(value.0)
    }
}

impl From<Block> for Gf2_128 {
    fn from(block: Block) -> Self {
        Gf2_128::new_from_block(block)
    }
}

impl Distribution<Gf2_128> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_128 {
        Gf2_128(self.sample(rng))
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    /// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
    fn mul(self, y: Self) -> Self::Output {
        /// See NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
        const R: u128 = 0xE1000000000000000000000000000000;

        let x = self.0;
        let mut z = 0u128;
        let mut v = y.0;

        for i in (0..128).rev() {
            if ((x >> i) & 1) == 1 {
                z ^= v;
            }
            v = (v >> 1) ^ ((v & 1) * R);
        }

        Gf2_128(z)
    }
}

impl Neg for Gf2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Field for Gf2_128 {
    const BIT_SIZE: u32 = 128;

    fn zero() -> Self {
        Self::new(0)
    }

    fn one() -> Self {
        Self::new(1)
    }

    fn two_pow(rhs: u32) -> Self {
        Self(1 << rhs)
    }

    fn get_bit(&self, n: usize) -> bool {
        (self.0 << n) & 1 == 1
    }

    /// Galois field inversion of 128-bit block
    fn inverse(self) -> Self {
        let mut a = self;
        let mut out = Self::one();
        for _ in 0..127 {
            a = a * a;
            out = out * a;
        }
        out
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl FromBits for Gf2_128 {
    fn from_lsb0(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_lsb0(iter))
    }

    fn from_msb0(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_msb0(iter))
    }
}

impl ToBits for Gf2_128 {
    fn into_lsb0(self) -> Vec<bool> {
        self.0.into_lsb0()
    }

    fn into_lsb0_boxed(self: Box<Self>) -> Vec<bool> {
        self.0.into_lsb0()
    }

    fn into_msb0(self) -> Vec<bool> {
        self.0.into_msb0()
    }

    fn into_msb0_boxed(self: Box<Self>) -> Vec<bool> {
        self.0.into_msb0()
    }
}

impl BlockSerialize for Gf2_128 {
    type Serialized = Block;

    fn to_blocks(self) -> Self::Serialized {
        self.into()
    }

    fn from_blocks(blocks: Self::Serialized) -> Self {
        blocks.into()
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2_128;
    use crate::fields::{
        tests::{test_field_basic, test_field_compute_product_repeated},
        Field,
    };
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use mpc_core::Block;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_gf2_128_basic() {
        test_field_basic::<Gf2_128>();
        assert_eq!(Gf2_128::new(0), Gf2_128::zero());
        assert_eq!(Gf2_128::new(1), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        test_field_compute_product_repeated::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_mul() {
        // Naive multiplication is the same here
        let a = Gf2_128::new(3);
        let b = Gf2_128::new(5);

        // Here we cannot calculate naively
        let c = Gf2_128::new(3);
        let d = Gf2_128::new(7);

        // Test vector from Intel® Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode
        let e = Gf2_128::new(0x7b5b54657374566563746f725d53475d);
        let f = Gf2_128::new(0x48692853686179295b477565726f6e5d);

        assert_eq!(a * b, b * a);
        assert_eq!(a * b, Gf2_128::new(15));
        assert_eq!(c * d, Gf2_128::new(9));
        assert_eq!(e * f, Gf2_128::new(0x40229a09a5ed12e7e4e10da323506d2));
    }

    #[test]
    // Test multiplication against RustCrypto
    fn test_gf2_128_against_ghash_impl() {
        let mut rng = ChaCha12Rng::seed_from_u64(0u64);
        let a = Block::random(&mut rng);
        let b = Block::random(&mut rng);

        let mut g = GHash::new(&a.to_be_bytes().into());
        g.update(&b.to_be_bytes().into());
        let expected = Block::from(g.finalize().into_bytes());

        let a = Gf2_128::new_from_block(a);
        let b = Gf2_128::new_from_block(b);
        let output: Block = (a * b).into();

        assert_eq!(expected, output);
    }
}
