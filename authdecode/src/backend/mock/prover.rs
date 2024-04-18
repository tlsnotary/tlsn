use crate::{
    backend::{
        mock::{MockProof, CHUNK_SIZE},
        traits::{Field, ProverBackend},
    },
    prover::error::ProverError,
    utils::boolvec_to_u8vec,
    Proof, ProofInput,
};
use num::{bigint::Sign, BigInt, BigUint};
use rand::{thread_rng, Rng};
use std::any::Any;

use super::MockField;

/// A mock prover backend.
pub struct MockProverBackend {}

impl MockProverBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProverBackend<MockField> for MockProverBackend {
    fn commit_plaintext(
        &self,
        mut plaintext: Vec<u8>,
    ) -> Result<(MockField, MockField), ProverError> {
        if plaintext.len() > self.chunk_size() {
            // TODO proper error
            return Err(ProverError::InternalError);
        }
        // Add random salt to plaintext and hash it.
        let mut rng = thread_rng();
        let salt: u128 = rng.gen();
        let salt_bytes = salt.to_be_bytes();
        plaintext.extend(salt_bytes);

        let hash_bytes = &hash(&plaintext);

        Ok((
            MockField::from_bytes_be(hash_bytes.to_vec()),
            MockField::from_bytes_be(salt_bytes.to_vec()),
        ))
    }

    fn commit_encoding_sum(
        &self,
        encoding_sum: MockField,
    ) -> Result<(MockField, MockField), ProverError> {
        // Add random salt to encoding_sum and hash it.
        let mut rng = thread_rng();
        let salt: u128 = rng.gen();
        let salt_bytes = salt.to_be_bytes();

        let mut enc_sum = encoding_sum.to_bytes_be();
        enc_sum.extend(salt_bytes);

        let hash_bytes = hash(&enc_sum);

        Ok((
            MockField::from_bytes_be(hash_bytes.to_vec()),
            MockField::from_bytes_be(salt_bytes.to_vec()),
        ))
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn prove(&self, input: Vec<ProofInput<MockField>>) -> Result<Vec<Proof>, ProverError> {
        // Use the default strategy of one proof for one chunk.
        Ok(input
            .into_iter()
            .map(|input| {
                Proof::new(
                    &MockProof::new(
                        input.plaintext,
                        input.plaintext_salt,
                        input.encoding_sum_salt,
                    )
                    .to_bytes(),
                )
            })
            .collect::<Vec<_>>())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
