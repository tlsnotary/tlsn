//! Traits for the prover backend and the verifier backend.

use crate::{
    prover::{ProverError, ProverInput},
    verifier::VerifierError,
    Proof, PublicInput,
};

#[cfg(any(test, feature = "fixtures"))]
use std::any::Any;

/// A trait for zk proof generation backend.
pub trait ProverBackend<F>
where
    F: Field,
{
    /// Creates a commitment to the plaintext.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    ///
    /// # Panics
    ///
    /// Panics if the length of the plaintext exceeds the allowed maximum.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to commit to.
    fn commit_plaintext(&self, plaintext: &[u8]) -> (F, F);

    /// Creates a commitment to the plaintext using the provided salt.
    ///
    /// Returns the commitment.
    ///
    /// # Panics
    ///
    /// Panics if the length of the plaintext exceeds the allowed maximum.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to commit to.
    /// * `salt` - The salt of the commitment.
    fn commit_plaintext_with_salt(&self, plaintext: &[u8], salt: &[u8]) -> F;

    /// Creates a commitment to the encoding sum.
    ///
    /// Returns the commitment and the salt used to create the commitment.
    ///
    /// # Arguments
    ///
    /// * `encoding_sum` - The sum of the encodings to commit to.
    fn commit_encoding_sum(&self, encoding_sum: F) -> (F, F);

    /// Given the `inputs` to the AuthDecode circuit, generates and returns `Proof`(s).
    ///
    /// # Arguments
    ///
    /// * `inputs` - A collection of circuit inputs. Each input proves a single chunk
    ///              of plaintext.
    fn prove(&self, inputs: Vec<ProverInput<F>>) -> Result<Vec<Proof>, ProverError>;

    /// The bytesize of a single chunk of plaintext. Does not include the salt.
    fn chunk_size(&self) -> usize;

    // Testing only. Used to downcast to a concrete type.
    #[cfg(any(test, feature = "fixtures"))]
    fn as_any(&self) -> &dyn Any;
}

/// A trait for zk proof verification backend.
pub trait VerifierBackend<F>: Send
where
    F: Field,
{
    /// Verifies multiple inputs against multiple proofs.
    ///
    /// The backend internally determines which inputs correspond to which proofs.
    fn verify(&self, inputs: Vec<PublicInput<F>>, proofs: Vec<Proof>) -> Result<(), VerifierError>;

    /// The bytesize of a single chunk of plaintext. Does not include the salt.
    fn chunk_size(&self) -> usize;
}

/// Methods for working with a field element.
pub trait Field {
    /// Creates a new field element from a little-endian byte representation of a scalar.
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;

    /// Returns the little-endian byte representation of a field element.
    fn to_bytes(self) -> Vec<u8>;

    /// Returns zero, the additive identity.
    fn zero() -> Self
    where
        Self: Sized;
}
