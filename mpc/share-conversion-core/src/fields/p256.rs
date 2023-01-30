//! This module implements the prime field of P256

use super::Field;
use ark_ff::{BigInt, BigInteger, Field as ArkField, FpConfig, MontBackend, One, Zero};
use ark_secp256r1::{fq::Fq, FqConfig};
use mpc_core::Block;
use num_bigint::{BigUint, ToBigUint};
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, Mul, Neg};

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct P256(pub(crate) Fq);

impl P256 {
    pub fn new(input: impl ToBigUint) -> Self {
        let input = input.to_biguint().expect("Unable to create field element");
        P256(Fq::from(input))
    }
}

impl From<P256> for Vec<Block> {
    fn from(value: P256) -> Self {
        let bytes = MontBackend::<FqConfig, 4>::into_bigint(value.0);
        let first = ((bytes.0[3] as u128) << 64) | bytes.0[2] as u128;
        let second = ((bytes.0[1] as u128) << 64) | bytes.0[0] as u128;
        vec![Block::new(first), Block::new(second)]
    }
}

impl From<Vec<Block>> for P256 {
    fn from(value: Vec<Block>) -> Self {
        let first = value[0].inner();
        let second = value[1].inner();

        let mut bytes: Vec<u8> = first.to_be_bytes().to_vec();
        bytes.extend_from_slice(&second.to_be_bytes());

        P256::new(BigUint::from_bytes_be(&bytes))
    }
}

impl Distribution<P256> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> P256 {
        P256(self.sample(rng))
    }
}

impl Add for P256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul for P256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Neg for P256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Field for P256 {
    const BIT_SIZE: u32 = 256;
    type OTEncoding = Vec<Block>;

    fn zero() -> Self {
        P256(<Fq as Zero>::zero())
    }

    fn one() -> Self {
        P256(<Fq as One>::one())
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
        MontBackend::<FqConfig, 4>::into_bigint(self.0)
            .get_bit(Self::BIT_SIZE as usize - n as usize - 1)
    }

    fn inverse(self) -> Self {
        P256(ArkField::inverse(&self.0).expect("Unable to invert field element"))
    }

    fn from_bits_be(bits: &[bool]) -> Self {
        P256(BigInt::from_bits_be(bits).into())
    }
}

#[cfg(test)]
mod tests {
    use mpc_core::Block;

    use super::P256;
    use crate::fields::{
        tests::{
            test_field_basic, test_field_bit_ops, test_field_block_conversion,
            test_field_compute_product_repeated,
        },
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

    #[test]
    fn test_p256_bit_ops() {
        test_field_bit_ops::<P256>();
    }

    #[test]
    fn test_p256_block_conversion() {
        test_field_block_conversion::<P256, Vec<Block>>();
    }
}
