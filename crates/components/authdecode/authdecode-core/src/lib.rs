//! Implementation of the AuthDecode protocol.
//!
//! The protocol performs authenticated decoding of encodings in zero knowledge.
//!
//! One of the use cases of AuthDecode is for the garbled circuits (GC) evaluator to produce a
//! zk-friendly hash commitment to either the GC input or the GC output, where computing such a
//! commitment directly using GC would be prohibitively expensive.
//!
//! The protocol consists of the following steps:
//! 1. The Prover commits to both the plaintext and the arithmetic sum of the active encodings of the
//!    bits of the plaintext. (The protocol assumes that the Prover ascertained beforehand that the
//!    active encodings are authentic.)
//! 2. The Prover obtains the full encodings of the plaintext bits from some outer context and uses
//!    them to create a zk proof, proving that during Step 1. they knew the correct active encodings
//!    of the plaintext and also proving that a hash commitment H is an authentic commitment to the
//!    plaintext.
//! 3. The Verifier verifies the proof and accepts H as an authentic hash commitment to the plaintext.
//!
//! Important: when using the protocol, you must ensure that the Prover obtains the full encodings
//! from an outer context only **after** they've made a commitment in Step 1.

pub mod backend;
pub mod encodings;
pub mod id;
pub mod msgs;
pub mod prover;
pub mod verifier;

#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use prover::Prover;
pub use verifier::Verifier;

use serde::{Deserialize, Serialize};

/// The statistical security parameter used by the protocol.
pub const SSP: usize = 40;

/// An opaque proof.
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct Proof(Vec<u8>);
impl Proof {
    /// Creates a new proof from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes from which to create the proof.
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

/// Public inputs to the AuthDecode circuit.
#[derive(Clone, Default)]
pub struct PublicInput<F> {
    /// The hash commitment to the plaintext.
    plaintext_hash: F,
    /// The hash commitment to the sum of the encodings.
    encoding_sum_hash: F,
    /// The sum of the encodings which encode the value 0 of a bit.
    zero_sum: F,
    /// An arithmetic difference between the encoding of bit value 1 and encoding of bit value 0 for
    /// each bit of the plaintext in LSB0 bit order.
    deltas: Vec<F>,
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::traits::{Field, ProverBackend, VerifierBackend},
        fixtures,
        mock::{MockBitIds, MockEncodingProvider},
        prover::{CommitmentData, ProofGenerated, Prover, ProverInput},
        verifier::{VerifiedSuccessfully, Verifier},
        Proof,
    };

    use rstest::*;
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        any::Any,
        cell::RefCell,
        ops::{Add, Sub},
    };

    #[fixture]
    #[once]
    fn commitment_data() -> Vec<CommitmentData<MockBitIds>> {
        fixtures::commitment_data()
    }

    #[fixture]
    #[once]
    fn encoding_provider() -> MockEncodingProvider<MockBitIds> {
        fixtures::encoding_provider()
    }

    // Tests the protocol with a mock backend.
    #[rstest]
    fn test_mock_backend(
        commitment_data: &[CommitmentData<MockBitIds>],
        encoding_provider: &MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            crate::backend::mock::backend_pair(),
            commitment_data,
            encoding_provider,
        );
    }

    // Tests the protocol with a mock halo2 prover and verifier.
    #[rstest]
    fn test_mock_halo2_backend(
        commitment_data: &[CommitmentData<MockBitIds>],
        encoding_provider: &MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            crate::backend::halo2::fixtures::backend_pair_mock(),
            commitment_data,
            encoding_provider,
        );
    }

    // Tests the protocol with a halo2 prover and verifier..
    #[ignore = "expensive"]
    #[rstest]
    fn test_halo2_backend(
        commitment_data: &[CommitmentData<MockBitIds>],
        encoding_provider: &MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            crate::backend::halo2::fixtures::backend_pair(),
            commitment_data,
            encoding_provider,
        );
    }

    // Runs the protocol with the given backends.
    // Returns the prover and the verifier in their finalized state.
    #[allow(clippy::type_complexity)]
    fn run_authdecode<F>(
        pair: (
            impl ProverBackend<F> + 'static,
            impl VerifierBackend<F> + 'static,
        ),
        commitment_data: &[CommitmentData<MockBitIds>],
        encoding_provider: &MockEncodingProvider<MockBitIds>,
    ) -> (
        Prover<MockBitIds, ProofGenerated<MockBitIds, F>, F>,
        Verifier<MockBitIds, VerifiedSuccessfully<MockBitIds, F>, F>,
    )
    where
        F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone,
    {
        let prover = Prover::new(Box::new(pair.0));
        let verifier = Verifier::new(Box::new(pair.1));

        let (prover, commitments) = prover.commit(commitment_data.to_vec()).unwrap();

        // Message types are checked during deserialization.
        let commitments = bincode::serialize(&commitments).unwrap();
        let commitments = bincode::deserialize(&commitments).unwrap();

        let verifier = verifier.receive_commitments(commitments).unwrap();

        // An encoding provider is instantiated with authenticated full encodings from external context.
        let (prover, proofs) = prover.prove(encoding_provider).unwrap();

        // Message types are checked durind deserialization.
        let proofs = bincode::serialize(&proofs).unwrap();
        let proofs = bincode::deserialize(&proofs).unwrap();

        let verifier = verifier.verify(proofs, encoding_provider).unwrap();

        (prover, verifier)
    }

    // Returns valid `ProofInput`s for the given backend pair which can be used as a fixture in
    // backend tests.
    pub fn proof_inputs_for_backend<
        F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone + 'static,
    >(
        prover: impl ProverBackend<F> + 'static,
        verifier: impl VerifierBackend<F> + 'static,
    ) -> Vec<ProverInput<F>> {
        // Wrap the prover backend.
        struct ProverBackendWrapper<F> {
            prover: Box<dyn ProverBackend<F>>,
            proof_inputs: RefCell<Option<Vec<ProverInput<F>>>>,
        }

        impl<F> ProverBackend<F> for ProverBackendWrapper<F>
        where
            F: Field
                + Add<Output = F>
                + Sub<Output = F>
                + Serialize
                + DeserializeOwned
                + Clone
                + 'static,
        {
            fn chunk_size(&self) -> usize {
                self.prover.chunk_size()
            }

            fn commit_encoding_sum(&self, encoding_sum: F) -> (F, F) {
                self.prover.commit_encoding_sum(encoding_sum)
            }

            fn commit_plaintext(&self, plaintext: &[u8]) -> (F, F) {
                self.prover.commit_plaintext(plaintext)
            }

            fn commit_plaintext_with_salt(&self, _plaintext: &[u8], _salt: &[u8]) -> F {
                unimplemented!()
            }

            fn prove(
                &self,
                input: Vec<ProverInput<F>>,
            ) -> Result<Vec<crate::Proof>, crate::prover::ProverError> {
                // Save proof inputs, return a dummy proof.
                *self.proof_inputs.borrow_mut() = Some(input);
                Ok(vec![Proof::new(&[0u8])])
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        // Wrap the verifier backend.
        struct VerifierBackendWrapper<F> {
            verifier: Box<dyn VerifierBackend<F>>,
        }

        impl<F> VerifierBackend<F> for VerifierBackendWrapper<F>
        where
            F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone,
        {
            fn chunk_size(&self) -> usize {
                self.verifier.chunk_size()
            }

            fn verify(
                &self,
                _inputs: Vec<crate::PublicInput<F>>,
                _proofs: Vec<Proof>,
            ) -> Result<(), crate::verifier::VerifierError> {
                Ok(())
            }
        }

        // Instantiate the backend pair.
        let prover_wrapper = ProverBackendWrapper {
            prover: Box::new(prover),
            proof_inputs: RefCell::new(None),
        };
        let verifier_wrapper = VerifierBackendWrapper {
            verifier: Box::new(verifier),
        };

        // Run the protocol.
        let (prover, _) = run_authdecode(
            (prover_wrapper, verifier_wrapper),
            &commitment_data(),
            &encoding_provider(),
        );

        // Extract proof inputs from the backend.
        prover
            .backend()
            .as_any()
            .downcast_ref::<ProverBackendWrapper<F>>()
            .unwrap()
            .proof_inputs
            .borrow()
            .clone()
            .unwrap()
    }
}
