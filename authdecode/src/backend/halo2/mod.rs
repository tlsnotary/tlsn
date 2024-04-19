use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Add, Sub};

use crate::backend::{halo2::utils::bytes_be_to_f, traits::Field};

mod circuit;
pub mod onetimesetup;
mod poseidon;
pub mod prover;
mod utils;
pub mod verifier;

lazy_static! {
    static ref PARAMS: ParamsKZG<Bn256> = onetimesetup::params();
}

/// The bytesize of one chunk of plaintext.
const CHUNK_SIZE: usize = circuit::FIELD_ELEMENTS * circuit::USABLE_BYTES;

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

impl Field for Bn256F {
    fn from_bytes_be(bytes: Vec<u8>) -> Self {
        Self {
            inner: bytes_be_to_f(bytes),
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

#[allow(clippy::from_over_into)]
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
    use crate::backend::halo2::onetimesetup::{proving_key, verification_key};

    pub fn backend_pair() -> (Prover, Verifier) {
        (
            Prover::new(proving_key()),
            Verifier::new(verification_key()),
        )
    }
}
