//! This module implements the extension field GF(2^128)

use crate::ShareConversionCoreError;

use super::Field;
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, Mul, Neg};

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct Gf2_128(pub(crate) u128);

impl Gf2_128 {
    pub fn new(input: u128) -> Self {
        Gf2_128(input)
    }

    #[cfg(test)]
    fn reverse_bits(self) -> Self {
        Self(self.0.reverse_bits())
    }
}

impl From<Gf2_128> for Vec<u8> {
    fn from(value: Gf2_128) -> Self {
        value.0.to_be_bytes().to_vec()
    }
}

impl TryFrom<Vec<u8>> for Gf2_128 {
    type Error = ShareConversionCoreError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: [u8; 16] = value
            .try_into()
            .map_err(|_| ShareConversionCoreError::DeserializeFieldElement)?;
        Ok(Self(u128::from_be_bytes(bytes)))
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
        /// R is the GCM polynomial in big-endian. In hex: "000000000000000000000000000000E1"
        const R: u128 = 135;

        let mut x = self.0;
        let y = rhs.0;

        let mut result: u128 = 0;
        for i in 0..128 {
            result ^= x * ((y >> i) & 1);
            x = (x << 1) ^ (((x >> 127) & 1) * R);
        }
        Self(result)
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
        if rhs == 0 {
            return Self::one();
        }

        let mut out = Self::new(2);
        for _ in 1..rhs {
            out = out * Self::new(2);
        }
        out
    }

    fn get_bit_be(&self, n: u32) -> bool {
        (self.0 >> (Self::BIT_SIZE - n - 1)) & 1 == 1
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

    fn from_bits_be(bits: &[bool]) -> Self {
        let mut out = Self::zero();
        for k in 0..Self::BIT_SIZE {
            out.0 |= (bits[k as usize] as u128) << (Self::BIT_SIZE - k - 1)
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
        assert_eq!(Gf2_128::new(1), Gf2_128::one());
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
        // Naive mutltiplication is the same here
        let a = Gf2_128::new(3);
        let b = Gf2_128::new(5);

        // Here we cannot calculate naively
        let c = Gf2_128::new(3);
        let d = Gf2_128::new(7);

        assert_eq!(a * b, Gf2_128::new(15));
        assert_eq!(c * d, Gf2_128::new(9));
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
        let output = (a.reverse_bits() * b.reverse_bits()).0.reverse_bits();
        assert_eq!(expected, output);
    }
}
