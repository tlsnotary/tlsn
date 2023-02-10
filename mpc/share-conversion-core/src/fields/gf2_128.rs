//! This module implements the extension field GF(2^128)

use super::Field;
use mpc_core::Block;
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, Mul, Neg};

/// A type for holding field elements of Gf(2^128)
///
/// Uses internally an  LSB0 encoding
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct Gf2_128(pub(crate) u128);

impl Gf2_128 {
    pub fn new(input: u128) -> Self {
        Gf2_128(input)
    }

    pub fn into_inner(self) -> u128 {
        self.0
    }
}

impl From<Gf2_128> for Block {
    fn from(value: Gf2_128) -> Self {
        Block::new(value.0)
    }
}

impl From<Block> for Gf2_128 {
    fn from(value: Block) -> Self {
        Gf2_128::new(value.inner())
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
    fn mul(self, rhs: Self) -> Self::Output {
        /// R is the GCM "special element" (see section 2.5 of "The Galois/Counter Mode of Operation (GCM)")
        /// in little-endian. In hex: "E1000000000000000000000000000000"
        const R: u128 = 299076299051606071403356588563077529600;

        let mut x = self.0;
        let y = rhs.0;

        let mut result = 0_u128;
        for i in (0..128).rev() {
            result ^= x * ((y >> i) & 1);
            x = (x >> 1) ^ ((x & 1) * R);
        }
        Gf2_128::new(result)
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
    type BlockEncoding = Block;

    fn zero() -> Self {
        Self::new(0)
    }

    fn one() -> Self {
        Self::new(1 << 127)
    }

    fn two_pow(rhs: u32) -> Self {
        if rhs == 0 {
            return Self::one();
        }

        let mut out = Self::new(1 << 126);
        for _ in 1..rhs {
            out = out * Self::new(1 << 126);
        }
        out
    }

    fn get_bit_msb0(&self, n: u32) -> bool {
        (self.0 >> n) & 1 == 1
    }

    /// Galois field inversion of 128-bit block
    fn inverse(self) -> Self {
        let mut a = self;
        let one = Self::one();
        let mut out = one;

        for _ in 0..127 {
            a = a * a;
            out = out * a;
        }
        out
    }

    fn from_bits_msb0(bits: &[bool]) -> Self {
        let mut out = Self::zero();
        for k in 0..bits.len() {
            out.0 |= (bits[k as usize] as u128) << k
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2_128;
    use crate::fields::{
        tests::{test_field_basic, test_field_bit_ops, test_field_compute_product_repeated},
        Field, UniformRand,
    };
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_gf2_128_basic() {
        test_field_basic::<Gf2_128>();
        assert_eq!(Gf2_128::new(0), Gf2_128::zero());
        assert_eq!(Gf2_128::new(1 << 127), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        test_field_compute_product_repeated::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_bit_ops() {
        test_field_bit_ops::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_mul() {
        // We reverse bits here, because we use an LSB0 encoding

        // Naive multiplication is the same here
        let a = Gf2_128::new(3_u128.reverse_bits());
        let b = Gf2_128::new(5_u128.reverse_bits());

        // Here we cannot calculate naively
        let c = Gf2_128::new(3_u128.reverse_bits());
        let d = Gf2_128::new(7_u128.reverse_bits());

        assert_eq!(a * b, Gf2_128::new(15_u128.reverse_bits()));
        assert_eq!(c * d, Gf2_128::new(9_u128.reverse_bits()));
    }

    #[test]
    // Test multiplication against RustCrypto
    fn test_gf2_128_against_ghash_impl() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: Gf2_128 = Gf2_128::rand(&mut rng);
        let b: Gf2_128 = Gf2_128::rand(&mut rng);

        let mut g = GHash::new(&a.0.to_be_bytes().into());
        g.update(&b.0.to_be_bytes().into());

        // Ghash will internally multiply a and b
        let expected = u128::from_be_bytes(g.finalize().into_bytes().into());
        let output = (a * b).0;
        assert_eq!(expected, output);
    }
}
