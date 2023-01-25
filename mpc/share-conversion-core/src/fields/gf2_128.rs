//! This module implements the extension field GF(2^128)

use super::Field;
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, BitXor, Mul, Neg, Shl, Shr, Sub};

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct Gf2_128(pub(crate) u128);

impl Gf2_128 {
    pub fn new(input: u128) -> Self {
        Gf2_128::from(input)
    }
}

impl From<u128> for Gf2_128 {
    fn from(value: u128) -> Self {
        Self(value.reverse_bits())
    }
}

impl From<Gf2_128> for u128 {
    fn from(value: Gf2_128) -> Self {
        value.0.reverse_bits()
    }
}

impl Distribution<Gf2_128> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_128 {
        Gf2_128(self.sample(rng))
    }
}

impl Field for Gf2_128 {
    const BIT_SIZE: usize = 128;

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1 << 127)
    }

    fn get_bit(&self, n: usize) -> bool {
        (self.0 >> n) & 1 == 1
    }

    /// Galois field inversion of 128-bit block
    fn inverse(mut self) -> Self {
        let one = Self::one();
        let mut out = one;

        for _ in 0..127 {
            self = self * self;
            out = out * self;
        }
        out
    }

    fn from_bits_be(bits: &[bool]) -> Self {
        Self::new(
            bits.iter()
                .fold(0, |result, bit| (result << 1) ^ *bit as u128),
        )
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 ^= rhs.0;
        self
    }
}

impl Sub for Gf2_128 {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 ^= rhs.0;
        self
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    /// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
    fn mul(mut self, rhs: Self) -> Self::Output {
        /// R is the GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
        const R: u128 = 299076299051606071403356588563077529600;

        let mut x = self.0;
        let y = rhs.0;

        let mut result: u128 = 0;
        for i in (0..128).rev() {
            result ^= x * ((y >> i) & 1);
            x = (x >> 1) ^ ((x & 1) * R);
        }
        self.0 = result;
        self
    }
}

impl Neg for Gf2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Shr<u32> for Gf2_128 {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self.0 = self.0 >> rhs;
        self
    }
}

impl Shl<u32> for Gf2_128 {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self.0 = self.0 << rhs;
        self
    }
}

impl BitXor<Self> for Gf2_128 {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.0 = self.0 ^ rhs.0;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{compute_product_repeated, Field};

    use super::Gf2_128;
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_gf2_128_basic() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: Gf2_128 = rng.gen();

        let zero = Gf2_128::zero();
        let one = Gf2_128::one();

        assert_eq!(a + zero, a);
        assert_eq!(a * zero, zero);
        assert_eq!(a * one, a);
        assert_eq!(a * a.inverse(), one);
        assert_eq!(a - a, zero);
        assert_eq!(Gf2_128::new(1), Gf2_128::one())
    }

    #[test]
    // Test multiplication against RustCrypto
    fn test_gf2_128_mul() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: Gf2_128 = rng.gen();
        let b: Gf2_128 = rng.gen();

        let mut g = GHash::new(&a.0.to_be_bytes().into());
        g.update(&b.0.to_be_bytes().into());
        // Ghash will internally multiply a and b
        let expected = g.finalize();

        assert_eq!(
            a * b,
            u128::from_be_bytes(expected.into_bytes().try_into().unwrap())
                .reverse_bits()
                .into()
        );
    }

    #[test]
    fn test_inverse() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: Gf2_128 = rng.gen();

        assert_eq!(a * a.inverse(), Gf2_128::one());
        assert_eq!(Gf2_128::one().inverse(), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: Gf2_128 = rng.gen();

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }
}
