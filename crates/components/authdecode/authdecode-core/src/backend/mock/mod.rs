use crate::backend::traits::Field;
use bincode;
use num::{bigint::Sign, BigInt};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Add, Sub};

pub mod circuit;
pub mod prover;
pub mod verifier;

pub use prover::MockProverBackend;
pub use verifier::MockVerifierBackend;

/// Chunk size in bytes.
pub(crate) const CHUNK_SIZE: usize = 300;

/// A mock field element.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct MockField {
    #[serde(
        serialize_with = "bigint_serialize",
        deserialize_with = "bigint_deserialize"
    )]
    inner: BigInt,
}

impl MockField {
    // Creates a new random MockField.
    pub fn random() -> Self {
        let mut random = [0u8; 32];
        thread_rng().fill(&mut random[..]);
        Self {
            inner: BigInt::from_bytes_le(Sign::Plus, &random),
        }
    }
}

impl Add for MockField {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl Sub for MockField {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
        }
    }
}

impl Field for MockField {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: BigInt::from_bytes_le(Sign::Plus, bytes),
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        let (_, inner_bytes) = self.inner.to_bytes_le();
        bytes[0..inner_bytes.len()].copy_from_slice(&inner_bytes);
        bytes.to_vec()
    }

    fn zero() -> Self {
        Self {
            inner: BigInt::from(0u8),
        }
    }
}

/// A mock proof.
///
/// Normally, the prover proves in zk the knowledge of private inputs which satisfy the circuit's
/// constraints. Here the private inputs are simply revealed without zk.
#[derive(Serialize, Deserialize)]
pub struct MockProof {
    plaintext: Vec<u8>,
    plaintext_salt: MockField,
    encoding_sum_salt: MockField,
}

impl MockProof {
    /// Creates a new mock proof.
    pub fn new(
        plaintext: Vec<u8>,
        plaintext_salt: MockField,
        encoding_sum_salt: MockField,
    ) -> Self {
        Self {
            plaintext,
            plaintext_salt,
            encoding_sum_salt,
        }
    }

    /// Serializes `self` into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Deserializes `self` from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        bincode::deserialize(&bytes).unwrap()
    }
}

fn bigint_serialize<S>(bigint: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let (sign, bytes) = bigint.to_bytes_be();
    assert!(sign == Sign::Plus);
    serializer.serialize_bytes(&bytes)
}

fn bigint_deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    Ok(BigInt::from_bytes_be(Sign::Plus, &bytes))
}

/// Returns a pair of mock backends.
pub fn backend_pair() -> (MockProverBackend, MockVerifierBackend) {
    (MockProverBackend::new(), MockVerifierBackend::new())
}
