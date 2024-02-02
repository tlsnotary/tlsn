use num::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod circuit;
pub mod prover;
pub mod verifier;
pub use prover::MockProverBackend;
pub use verifier::MockVerifierBackend;

/// Chunk size in bits.
pub const CHUNK_SIZE: usize = 300 * 8;

/// A mock proof.
///
/// Normally, the prover proves in zk the knowledge of private inputs which satisfy the circuit's
/// constraints. Here the private inputs are simply revealed without zk.
#[derive(Serialize, Deserialize)]
pub struct MockProof {
    plaintext: Vec<bool>,
    #[serde(
        serialize_with = "biguint_serialize",
        deserialize_with = "biguint_deserialize"
    )]
    plaintext_salt: BigUint,
    #[serde(
        serialize_with = "biguint_serialize",
        deserialize_with = "biguint_deserialize"
    )]
    encoding_sum_salt: BigUint,
}

impl MockProof {
    /// Creates a new mock proof.
    pub fn new(plaintext: Vec<bool>, plaintext_salt: BigUint, encoding_sum_salt: BigUint) -> Self {
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

fn biguint_serialize<S>(biguint: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(&biguint.to_bytes_be())
}

fn biguint_deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{MockProverBackend, MockVerifierBackend};

    pub fn backend_pair() -> (MockProverBackend, MockVerifierBackend) {
        (MockProverBackend::new(), MockVerifierBackend::new())
    }
}
