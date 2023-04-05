use std::default;

use serde::Serialize;

#[derive(Serialize, Clone)]
pub enum Commitment {
    Blake3(Blake3),
}

impl Default for Commitment {
    fn default() -> Self {
        Commitment::Blake3(Blake3::default())
    }
}

/// A blake3 digest of the encoding of the plaintext
#[derive(Serialize, Clone, Default)]
pub struct Blake3 {
    labels_hash: [u8; 32],
}

impl Blake3 {
    pub fn labels_hash(&self) -> &[u8; 32] {
        &self.labels_hash
    }
}
