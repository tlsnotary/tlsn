use crate::{
    backend::mock::{MockProof, CHUNK_SIZE},
    prover::{backend::Backend as ProverBackend, error::ProverError},
    utils::boolvec_to_u8vec,
    Proof, ProofInput,
};
use num::BigUint;
use rand::{thread_rng, Rng};

/// A mock prover backend.
pub struct MockProverBackend {}

impl MockProverBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProverBackend for MockProverBackend {
    fn commit_plaintext(&self, plaintext: Vec<bool>) -> Result<(BigUint, BigUint), ProverError> {
        if plaintext.len() > self.chunk_size() {
            // TODO proper error
            return Err(ProverError::InternalError);
        }
        // Generate random salt and add it to the plaintext.
        let mut rng = thread_rng();
        let salt: u128 = rng.gen();
        let salt = salt.to_be_bytes();
        let salt_as_biguint = BigUint::from_bytes_be(&salt);

        let mut plaintext = boolvec_to_u8vec(&plaintext);
        plaintext.extend(salt);
        let plaintext_hash = BigUint::from_bytes_be(&hash(&plaintext));

        Ok((plaintext_hash, salt_as_biguint))
    }

    fn commit_encoding_sum(
        &self,
        encoding_sum: BigUint,
    ) -> Result<(BigUint, BigUint), ProverError> {
        // Generate random salt
        let mut rng = thread_rng();
        let salt: u128 = rng.gen();
        let salt = salt.to_be_bytes();
        let salt_as_biguint = BigUint::from_bytes_be(&salt);

        let mut enc_sum = encoding_sum.to_bytes_be();
        enc_sum.extend(salt);
        let enc_sum_hash = BigUint::from_bytes_be(&hash(&enc_sum));

        Ok((enc_sum_hash, salt_as_biguint))
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn prove(&self, input: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
        // Use the default strategy of one proof for one chunk.
        Ok(input
            .iter()
            .map(|input| {
                MockProof::new(
                    input.plaintext.clone(),
                    input.plaintext_salt.clone(),
                    input.encoding_sum_salt.clone(),
                )
                .to_bytes()
            })
            .collect::<Vec<_>>())
    }
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
