use crate::{
    backend::{
        mock::{MockField, MockProof, CHUNK_SIZE},
        traits::{Field, ProverBackend},
    },
    prover::{ProverError, ProverInput},
    Proof,
};

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
    fn commit_plaintext(&self, plaintext: &[u8]) -> (MockField, MockField) {
        assert!(plaintext.len() <= self.chunk_size());

        let salt = MockField::random();
        let mut plaintext = plaintext.to_vec();
        plaintext.extend(salt.clone().to_bytes());

        (MockField::from_bytes(&hash(&plaintext)), salt)
    }

    fn commit_plaintext_with_salt(&self, _plaintext: &[u8], _salt: &[u8]) -> MockField {
        unimplemented!()
    }

    fn commit_encoding_sum(&self, encoding_sum: MockField) -> (MockField, MockField) {
        let salt = MockField::random();
        let mut enc_sum = encoding_sum.to_bytes();
        enc_sum.extend(salt.clone().to_bytes());

        (MockField::from_bytes(&hash(&enc_sum)), salt)
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
