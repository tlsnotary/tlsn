use crate::{prover::error::ProverError, Proof, ProofInput};
use num::{BigInt, BigUint};

/// A trait for zk proof generation backend.
pub trait Backend {
    /// Creates a commitment to the plaintext, padding the plaintext if necessary.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    fn commit_plaintext(&self, plaintext: Vec<bool>) -> Result<(BigUint, BigUint), ProverError>;

    /// Creates a commitment to the encoding sum.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    fn commit_encoding_sum(&self, encoding_sum: BigUint)
        -> Result<(BigUint, BigUint), ProverError>;

    /// Given the `input` to the AuthDecode zk circuit, generates and returns `Proof`(s)
    fn prove(&self, input: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError>;

    /// How many bits of [Plaintext] can fit into one [Chunk]. This does not
    /// include the [Salt] of the hash - which takes up the remaining least bits
    /// of the last field element of each chunk.
    fn chunk_size(&self) -> usize;
}
