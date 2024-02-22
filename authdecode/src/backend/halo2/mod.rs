use std::ops::{Add, Sub};

use crate::{backend::traits::Field, utils::bits_to_biguint};
use halo2_proofs::halo2curves::bn256::Fr;
use num::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utils::biguint_to_f;

mod circuit;
pub mod onetimesetup;
mod poseidon;
pub mod prover;
mod utils;
pub mod verifier;

/// The amount of LSBs of a field element that are being used.
const USEFUL_BITS: usize = 253;

/// The size of the chunk of plaintext
/// We use 14 field elements. Only [USEFUL_BITS] of each field element are used.
const CHUNK_SIZE: usize = 3542;

/// A field element of the Bn256 curve.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bn256F {
    #[serde(serialize_with = "fr_serialize", deserialize_with = "fr_deserialize")]
    pub inner: Fr,
}
impl Bn256F {
    pub fn new(inner: Fr) -> Self {
        Self { inner }
    }
}

impl Bn256F {
    pub fn into_bytes_be(&self) -> Vec<u8> {
        let mut bytes = self.inner.to_bytes();
        bytes.reverse();
        bytes.to_vec()
    }
}

impl Field for Bn256F {
    fn from_bytes_be(bytes: Vec<u8>) -> Self {
        Self {
            inner: biguint_to_f(&BigUint::from_bytes_be(&bytes)),
        }
    }

    fn zero() -> Self {
        Self { inner: Fr::zero() }
    }
}

impl Add for Bn256F {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl Sub for Bn256F {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
        }
    }
}

impl Into<Fr> for Bn256F {
    fn into(self) -> Fr {
        self.inner
    }
}

fn fr_serialize<S>(fr: &Fr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(&fr.to_bytes())
}

fn fr_deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: [u8; 32] = Vec::deserialize(deserializer)?
        .try_into()
        .map_err(|_| serde::de::Error::custom("the amount of bytes is not 32"))?;

    let res = Fr::from_bytes(&bytes);
    if res.is_none().into() {
        return Err(serde::de::Error::custom(
            "the bytes are not a valid field element",
        ));
    }
    Ok(res.unwrap())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{prover::Prover, verifier::Verifier};

    pub fn backend_pair() -> (Prover, Verifier) {
        let params = super::onetimesetup::OneTimeSetup::params();

        let proving_key = super::onetimesetup::OneTimeSetup::proving_key(params.clone());
        let verification_key = super::onetimesetup::OneTimeSetup::verification_key(params);

        (Prover::new(proving_key), Verifier::new(verification_key))
    }
}
