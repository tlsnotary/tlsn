use crate::{
    backend::{mock::CHUNK_SIZE, traits::VerifierBackend as Backend},
    verifier::{error::VerifierError, verifier::VerificationInputs},
    Proof,
};

use super::{circuit::is_circuit_satisfied, MockField, MockProof};

/// A mock verifier backend.
#[derive(Default)]
pub struct MockVerifierBackend {}

impl MockVerifierBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl Backend<MockField> for MockVerifierBackend {
    fn verify(
        &self,
        inputs: Vec<VerificationInputs<MockField>>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // Use the default strategy of one proof for one chunk.
        assert!(proofs.len() == inputs.len());
        for (proof, input) in proofs.iter().zip(inputs) {
            let proof = MockProof::from_bytes(proof.0.to_vec());
            if !is_circuit_satisfied(
                input.plaintext_hash,
                input.encoding_sum_hash,
                input.zero_sum,
                input.deltas,
                proof.plaintext,
                proof.plaintext_salt,
                proof.encoding_sum_salt,
            ) {
                return Err(VerifierError::VerificationFailed);
            };
        }

        Ok(())
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }
}
