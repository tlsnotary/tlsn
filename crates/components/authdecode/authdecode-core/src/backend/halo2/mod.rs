//! Halo2 backend for AuthDecode.

use crate::{
    backend::{
        halo2::{
            circuit::{BITS_PER_LIMB, FIELD_ELEMENTS},
            utils::{bytes_to_f, slice_to_columns},
        },
        traits::Field,
    },
    PublicInput,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};

use lazy_static::lazy_static;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Add, Sub};

mod circuit;
pub mod onetimesetup;
pub mod poseidon;
pub mod prover;
mod utils;
pub mod verifier;

#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

lazy_static! {
    static ref PARAMS: ParamsKZG<Bn256> = onetimesetup::params();
}

/// The bytesize of one chunk of plaintext.
pub const CHUNK_SIZE: usize = circuit::FIELD_ELEMENTS * circuit::USABLE_BYTES;

/// A field element of the Bn256 curve.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Bn256F {
    #[serde(serialize_with = "fr_serialize", deserialize_with = "fr_deserialize")]
    inner: Fr,
}
impl Bn256F {
    /// Creates a new Bn256 field element.
    pub fn new(inner: Fr) -> Self {
        Self { inner }
    }

    /// Consumes self, returning the inner value.
    pub fn into_inner(self) -> Fr {
        self.inner
    }
}

impl Field for Bn256F {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: bytes_to_f(bytes),
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
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

impl From<Fr> for Bn256F {
    fn from(value: Fr) -> Self {
        Bn256F::new(value)
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fr> for &Bn256F {
    fn into(self) -> Fr {
        self.inner
    }
}

// Serializes the `Fr` type into bytes.
fn fr_serialize<S>(fr: &Fr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(&fr.to_bytes())
}

// Deserializes the `Fr` type from bytes.
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

/// Prepares instance columns.
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all))]
fn prepare_instance(input: &PublicInput<Bn256F>, usable_bytes: usize) -> Vec<Vec<Fr>> {
    let deltas = input
        .deltas
        .iter()
        .map(|f: &Bn256F| f.inner)
        .collect::<Vec<_>>();

    // Arrange deltas in instance columns.
    let mut instance_columns = slice_to_columns(
        &deltas,
        usable_bytes * 8,
        BITS_PER_LIMB * 4,
        FIELD_ELEMENTS * 4,
        BITS_PER_LIMB,
    );

    // Add another column with public inputs.
    instance_columns.push(vec![
        input.plaintext_hash.inner,
        input.encoding_sum_hash.inner,
        input.zero_sum.inner,
    ]);

    instance_columns
}
