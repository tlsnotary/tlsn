//! This module implements the prime field of P256

use super::Field;
use ark_ff::{BigInt, BigInteger, Field as ArkField, One, Zero};
use ark_secp256r1::fq::Fq;
use num_bigint::{BigUint, ToBigUint};
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, BitXor, Mul, Neg, Shl, Shr, Sub};

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct P256(pub(crate) Fq);

impl P256 {
    pub fn new(input: impl ToBigUint) -> Self {
        let input = input.to_biguint().expect("Unable to create field element");
        P256::from(input)
    }
}

impl From<BigUint> for P256 {
    fn from(value: BigUint) -> Self {
        P256(Fq::from(value))
    }
}

impl From<P256> for Vec<u8> {
    fn from(value: P256) -> Self {
        value.0 .0.to_bytes_be()
    }
}

impl Distribution<P256> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> P256 {
        P256(self.sample(rng))
    }
}

impl Add for P256 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl Sub for P256 {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl Mul for P256 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl Neg for P256 {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.0 = -self.0;
        self
    }
}

impl Shr<u32> for P256 {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        for _ in 0..rhs {
            self.0 .0.divn(rhs);
        }
        self
    }
}

impl Shl<u32> for P256 {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        for _ in 0..rhs {
            self.0 .0.muln(rhs);
        }
        self
    }
}

impl BitXor<Self> for P256 {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        for (a, b) in self.0 .0 .0.iter_mut().zip(rhs.0 .0 .0) {
            *a ^= b
        }
        self
    }
}

impl Field for P256 {
    const BIT_SIZE: usize = 256;

    fn zero() -> Self {
        P256(<Fq as Zero>::zero())
    }

    fn one() -> Self {
        P256(<Fq as One>::one())
    }

    fn get_bit(&self, n: usize) -> bool {
        self.0 .0.get_bit(n)
    }

    fn inverse(mut self) -> Self {
        self.0 = ArkField::inverse(&self.0).expect("Unable to invert field element");
        self
    }

    fn from_bits_be(bits: &[bool]) -> Self {
        P256(BigInt::from_bits_be(bits).into())
    }
}

#[cfg(test)]
mod tests {
    use super::P256;
    use crate::fields::{
        tests::{test_field_basic, test_field_compute_product_repeated},
        Field,
    };

    #[test]
    fn test_p256_basic() {
        test_field_basic::<P256>();
        assert_eq!(P256::new(0), P256::zero());
        assert_eq!(P256::new(1), P256::one());
    }

    #[test]
    fn test_p256_compute_product_repeated() {
        test_field_compute_product_repeated::<P256>();
    }
}
