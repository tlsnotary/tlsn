use crate::HashCommitment;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub enum Commitment {
    Blake3(Blake3),
}

/// A blake3 digest of the encoding of the plaintext
#[derive(Serialize, Deserialize, Clone)]
pub struct Blake3 {
    /// A salted hash of the encoding of the plaintext
    encoding_hash: HashCommitment,
}

impl Blake3 {
    pub fn new(encoding_hash: HashCommitment) -> Self {
        Self { encoding_hash }
    }

    pub fn encoding_hash(&self) -> &HashCommitment {
        &self.encoding_hash
    }
}
