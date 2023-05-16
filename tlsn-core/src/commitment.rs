use mpc_core::hash::Hash;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub enum Commitment {
    Blake3(Blake3),
}

/// A blake3 digest of the encoding of the plaintext
#[derive(Serialize, Deserialize, Clone)]
pub struct Blake3 {
    /// A salted hash of the encoding of the plaintext
    encoding_hash: Hash,
}

impl Blake3 {
    pub fn new(encoding_hash: Hash) -> Self {
        Self { encoding_hash }
    }

    pub fn encoding_hash(&self) -> &Hash {
        &self.encoding_hash
    }
}
