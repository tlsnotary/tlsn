//! Implementation of the AuthDecode protocol.
//! The protocol performs authenticated decoding of encodings in zero knowledge.
//!
//! One of the use cases of AuthDecode is for the garbled circuits (GC) evaluator to produce
//! a zk-friendly hash commitment to the GC output, where computing such a commitment directly
//! inside the circuit would be prohibitively expensive.
//!
//! TODO: the high level steps of the protocol.

pub mod backend;
pub mod encodings;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod id;
pub mod mock;
pub mod msgs;
pub mod prover;
pub mod verifier;

pub use prover::prover::Prover;
pub use verifier::verifier::Verifier;

use serde::{Deserialize, Serialize};

/// Statistical security parameter used by the protocol.
pub const SSP: usize = 40;

/// An opaque proof.
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct Proof(Vec<u8>);
impl Proof {
    /// Creates a new proof from bytes.
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::traits::{Field, ProverBackend, VerifierBackend},
        fixtures,
        mock::{MockBitIds, MockEncodingProvider},
        prover::{
            commitment::CommitmentData,
            prover::{ProofInput, Prover},
            state::ProofGenerated,
        },
        verifier::{state::VerifiedSuccessfully, verifier::Verifier},
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
    fn commitment_data() -> Vec<CommitmentData<MockBitIds>> {
        fixtures::commitment_data()
    }

    #[fixture]
    fn encoding_provider() -> MockEncodingProvider<MockBitIds> {
        fixtures::encoding_provider()
    }

    // Tests the protocol with a mock backend.
    #[rstest]
    fn test_mock_backend(
        commitment_data: Vec<CommitmentData<MockBitIds>>,
        encoding_provider: MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            crate::backend::mock::backend_pair(),
            commitment_data,
            encoding_provider,
        );
    }

    // Tests the protocol with a halo2 backend.
    #[rstest]
    fn test_halo2_backend(
        commitment_data: Vec<CommitmentData<MockBitIds>>,
        encoding_provider: MockEncodingProvider<MockBitIds>,
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
        commitment_data: Vec<CommitmentData<MockBitIds>>,
        encoding_provider: MockEncodingProvider<MockBitIds>,
    ) -> (
        Prover<MockBitIds, ProofGenerated<MockBitIds, F>, F>,
        Verifier<MockBitIds, VerifiedSuccessfully<MockBitIds, F>, F>,
    )
    where
        F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone,
    {
        let prover = Prover::new(Box::new(pair.0));
        let verifier = Verifier::new(Box::new(pair.1));

        let (prover, commitments) = prover.commit(&commitment_data).unwrap();

        // Message types are checked durind deserialization.
        let commitments = bincode::serialize(&commitments).unwrap();
        let commitments = bincode::deserialize(&commitments).unwrap();

        let verifier = verifier
            .receive_commitments(commitments, encoding_provider.clone())
            .unwrap();

        // An encoding provider is instantiated with authenticated full encodings from external context.
        let (prover, proofs) = prover.prove(encoding_provider).unwrap();

        // Message types are checked durind deserialization.
        let proofs = bincode::serialize(&proofs).unwrap();
        let proofs = bincode::deserialize(&proofs).unwrap();

        let verifier = verifier.verify(proofs).unwrap();

        (prover, verifier)
    }

    // Returns valid `ProofInput`s for the given backend pair which can be used as a fixture in
    // backend tests.
    pub fn proof_inputs_for_backend<
        F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone + 'static,
    >(
        prover: impl ProverBackend<F> + 'static,
        verifier: impl VerifierBackend<F> + 'static,
    ) -> Vec<ProofInput<F>> {
        // Wrap the prover backend.
        struct ProverBackendWrapper<F> {
            prover: Box<dyn ProverBackend<F>>,
            proof_inputs: RefCell<Option<Vec<ProofInput<F>>>>,
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

            fn commit_plaintext(&self, plaintext: Vec<u8>) -> (F, F) {
                self.prover.commit_plaintext(plaintext)
            }

            fn prove(
                &self,
                input: Vec<ProofInput<F>>,
            ) -> Result<Vec<crate::Proof>, crate::prover::error::ProverError> {
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
                _inputs: Vec<crate::verifier::verifier::VerificationInputs<F>>,
                _proofs: Vec<Proof>,
            ) -> Result<(), crate::verifier::error::VerifierError> {
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
            commitment_data(),
            encoding_provider(),
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
