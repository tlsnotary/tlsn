use crate::{
    backend::{
        mock::{circuit::is_circuit_satisfied, MockField, MockProof, CHUNK_SIZE},
        traits::VerifierBackend as Backend,
    },
    verifier::VerifierError,
    Proof, PublicInput,
};

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
        inputs: Vec<PublicInput<MockField>>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // Using the default strategy of one proof for one chunk.
        if inputs.len() != proofs.len() {
            return Err(VerifierError::WrongProofCount(inputs.len(), proofs.len()));
        }

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
                return Err(VerifierError::VerificationFailed(
                    "Mock circuit was not satisfied".to_string(),
                ));
            };
        }

        Ok(())
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }
}
