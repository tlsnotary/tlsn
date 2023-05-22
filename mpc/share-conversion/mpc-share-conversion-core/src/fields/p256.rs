//! This module implements the prime field of P256

use std::ops::{Add, Mul, Neg};

use ark_ff::{BigInt, BigInteger, Field as ArkField, FpConfig, MontBackend, One, Zero};
use ark_secp256r1::{fq::Fq, FqConfig};
use num_bigint::ToBigUint;
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};

use mpc_core::{Block, BlockSerialize};
use utils::bits::{FromBits, ToBits};

use super::Field;

/// A type for holding field elements of P256
///
/// Uses internally an MSB0 encoding
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "[Block; 2]")]
#[serde(from = "[Block; 2]")]
pub struct P256(pub(crate) Fq);

opaque_debug::implement!(P256);

impl P256 {
    /// Creates a new field element
    pub fn new(input: impl ToBigUint) -> Self {
        let input = input.to_biguint().expect("Unable to create field element");
        P256(Fq::from(input))
    }
}

impl From<P256> for [Block; 2] {
    fn from(value: P256) -> Self {
        let bytes = MontBackend::<FqConfig, 4>::into_bigint(value.0);
        let first = ((bytes.0[3] as u128) << 64) | bytes.0[2] as u128;
        let second = ((bytes.0[1] as u128) << 64) | bytes.0[0] as u128;
        [Block::new(first), Block::new(second)]
    }
}

impl From<[Block; 2]> for P256 {
    fn from(value: [Block; 2]) -> Self {
        let first = (value[0].inner() >> 64) as u64;
        let second = value[0].inner() as u64;
        let third = (value[1].inner() >> 64) as u64;
        let fourth = value[1].inner() as u64;

        let big_int = BigInt::new([fourth, third, second, first]);

        P256(
            MontBackend::<FqConfig, 4>::from_bigint(big_int)
                .expect("Unable to create field element"),
        )
    }
}

impl From<[u8; 32]> for P256 {
    fn from(value: [u8; 32]) -> Self {
        let first = u128::from_be_bytes(value[..16].try_into().unwrap());
        let second = u128::from_be_bytes(value[16..].try_into().unwrap());
        P256::from([Block::new(first), Block::new(second)])
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

    fn zero() -> Self {
        P256(<Fq as Zero>::zero())
    }

    fn one() -> Self {
        P256(<Fq as One>::one())
    }

    fn two_pow(rhs: u32) -> Self {
        let mut out = <Fq as One>::one();
        for _ in 0..rhs {
            MontBackend::<FqConfig, 4>::double_in_place(&mut out);
        }

        P256(out)
    }

    fn get_bit(&self, n: usize) -> bool {
        MontBackend::<FqConfig, 4>::into_bigint(self.0).get_bit(n)
    }

    fn inverse(self) -> Self {
        P256(ArkField::inverse(&self.0).expect("Unable to invert field element"))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        BigInt::to_bytes_le(&MontBackend::<FqConfig, 4>::into_bigint(self.0))
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        BigInt::to_bytes_be(&MontBackend::<FqConfig, 4>::into_bigint(self.0))
    }
}

impl FromBits for P256 {
    fn from_lsb0(iter: impl IntoIterator<Item = bool>) -> Self {
        P256(BigInt::from_bits_le(&iter.into_iter().collect::<Vec<bool>>()).into())
    }

    fn from_msb0(iter: impl IntoIterator<Item = bool>) -> Self {
        P256(BigInt::from_bits_be(&iter.into_iter().collect::<Vec<bool>>()).into())
    }
}

impl ToBits for P256 {
    fn into_lsb0(self) -> Vec<bool> {
        (0..256).map(|i| self.get_bit(i)).collect()
    }

    fn into_lsb0_boxed(self: Box<Self>) -> Vec<bool> {
        (0..256).map(|i| self.get_bit(i)).collect()
    }

    fn into_msb0(self) -> Vec<bool> {
        (0..256).map(|i| self.get_bit(i)).rev().collect()
    }

    fn into_msb0_boxed(self: Box<Self>) -> Vec<bool> {
        (0..256).map(|i| self.get_bit(i)).rev().collect()
    }
}

impl BlockSerialize for P256 {
    type Serialized = [Block; 2];

    fn to_blocks(self) -> Self::Serialized {
        self.into()
    }

    fn from_blocks(blocks: Self::Serialized) -> Self {
        blocks.into()
    }
}

#[cfg(test)]
mod tests {
    use super::P256;
    use crate::fields::{
        tests::{test_field_basic, test_field_bit_ops, test_field_compute_product_repeated},
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
}
