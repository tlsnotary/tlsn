use crate::{
    backend::mock::CHUNK_SIZE,
    verifier::{backend::Backend, error::VerifierError, verifier::VerificationInput},
    Proof,
};

use super::{circuit::is_circuit_satisfied, MockProof};

/// A mock verifier backend.
pub struct MockVerifierBackend {}

impl MockVerifierBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl Backend for MockVerifierBackend {
    fn verify(
        &self,
        inputs: Vec<VerificationInput>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // Use the default strategy of one proof for one chunk.
        assert!(proofs.len() == inputs.len());
        for (proof, input) in proofs.iter().zip(inputs) {
            let proof = MockProof::from_bytes(proof.to_vec());
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
