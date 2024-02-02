use crate::{
    verifier::{error::VerifierError, verifier::VerificationInput},
    Proof,
};

/// A trait for zk proof verification backend.
pub trait Backend {
    /// Verifies multiple inputs against multiple proofs.
    /// Which inputs correspond to which proof is determined internally by the backend.
    fn verify(
        &self,
        inputs: Vec<VerificationInput>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError>;

    /// How many bits of [Plaintext] can fit into one [Chunk]. This does not
    /// include the [Salt] of the hash - which takes up the remaining least bits
    /// of the last field element of each chunk.
    fn chunk_size(&self) -> usize;
}
