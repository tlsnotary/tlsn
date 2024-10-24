use crate::{
    backend::{
        mock::{MockField, MockProof, CHUNK_SIZE},
        traits::{Field, ProverBackend},
    },
    prover::{ProverError, ProverInput},
    Proof,
};

use rand::{thread_rng, Rng};

#[cfg(any(test, feature = "fixtures"))]
use std::any::Any;

/// A mock prover backend.
#[derive(Default)]
pub struct MockProverBackend {}

impl MockProverBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProverBackend<MockField> for MockProverBackend {
    fn commit_plaintext(&self, mut plaintext: Vec<u8>) -> (MockField, MockField) {
        assert!(plaintext.len() <= self.chunk_size());

        // Add random salt to plaintext and hash it.
        let salt: [u8; 16] = thread_rng().gen();
        plaintext.extend(salt);

        let hash_bytes = &hash(&plaintext);

        (
            MockField::from_bytes_be(hash_bytes.to_vec()),
            MockField::from_bytes_be(salt.to_vec()),
        )
    }

    fn commit_plaintext_with_salt(&self, _plaintext: Vec<u8>, _salt: MockField) -> MockField {
        unimplemented!()
    }

    fn commit_encoding_sum(&self, encoding_sum: MockField) -> (MockField, MockField) {
        // Add random salt to encoding_sum and hash it.
        let salt: [u8; 16] = thread_rng().gen();

        let mut enc_sum = encoding_sum.to_bytes_be();
        enc_sum.extend(salt);

        let hash_bytes = hash(&enc_sum);

        (
            MockField::from_bytes_be(hash_bytes.to_vec()),
            MockField::from_bytes_be(salt.to_vec()),
        )
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn prove(&self, input: Vec<ProverInput<MockField>>) -> Result<Vec<Proof>, ProverError> {
        // Use the default strategy of one proof for one chunk.
        Ok(input
            .into_iter()
            .map(|input| {
                Proof::new(
                    &MockProof::new(
                        input.private().plaintext().clone(),
                        input.private().plaintext_salt().clone(),
                        input.private().encoding_sum_salt().clone(),
                    )
                    .to_bytes(),
                )
            })
            .collect::<Vec<_>>())
    }

    #[cfg(any(test, feature = "fixtures"))]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
