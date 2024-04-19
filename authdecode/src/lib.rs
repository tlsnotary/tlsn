//! Implementation of the AuthDecode protocol.
//! The protocol performs authenticated decoding of encodings in zero knowledge.
//!
//! One of the use cases of AuthDecode is for the garbled circuits (GC) evaluator to produce
//! a zk-friendly hash commitment to the GC output, where computing such a commitment directly
//! inside the circuit would be prohibitively expensive.
//!
//! TODO: the high level steps of the protocol.

#[allow(unused_imports)]
pub mod backend;
pub mod bitid;
pub mod encodings;
pub mod mock;
pub mod msgs;
pub mod prover;
pub mod utils;
pub mod verifier;

use std::any::Any;

use serde::{Deserialize, Serialize};

use crate::prover::prover::ProofInput;

/// Statistical security parameter used by the protocol.
pub const SSP: usize = 40;

/// An opaque proof.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Proof(Vec<u8>);
impl Proof {
    /// Creates a new proof from bytes.
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::traits::{Field, ProverBackend, VerifierBackend},
        encodings::FullEncodings,
        mock::{Direction, MockBitIds, MockEncodingProvider},
        prover::{
            commitment::CommitmentData,
            prover::{ProofInput, Prover},
            state::ProofCreated,
        },
        utils::choose,
        verifier::{state::VerifiedSuccessfully, verifier::Verifier},
        AsAny, Proof, SSP,
    };

    use itybity::ToBits;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        any::Any,
        cell::RefCell,
        ops::{Add, Sub},
    };

    // The size of plaintext in bytes;
    const PLAINTEXT_SIZE: usize = 1000;

    #[test]
    // Tests the protocol with a mock backend.
    fn test_mock_backend() {
        run_authdecode(crate::backend::mock::tests::backend_pair());
    }

    #[test]
    // Tests the protocol with halo2 backend.
    fn test_halo2_backend() {
        run_authdecode(crate::backend::halo2::tests::backend_pair());
    }

    // Runs the protocol with the given backends.
    // Returns the prover and the verifier in their finalized state.
    #[allow(clippy::type_complexity)]
    fn run_authdecode<F>(
        pair: (
            impl ProverBackend<F> + 'static,
            impl VerifierBackend<F> + 'static,
        ),
    ) -> (
        Prover<MockBitIds, ProofCreated<MockBitIds, F>, F>,
        Verifier<MockBitIds, VerifiedSuccessfully<MockBitIds, F>, F>,
    )
    where
        F: Field + Add<Output = F> + Sub<Output = F> + Serialize + DeserializeOwned + Clone,
    {
        let prover = Prover::new(Box::new(pair.0));
        let verifier = Verifier::new(Box::new(pair.1));

        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Generate random plaintext.
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(PLAINTEXT_SIZE)
            .collect();

        // Generate Verifier's full encodings for each bit of the plaintext. The length of an encoding
        // is 40 bits.
        let mut full_encodings = [[[0u8; SSP / 8]; 2]; PLAINTEXT_SIZE * 8];
        for elem in full_encodings.iter_mut() {
            *elem = rng.gen();
        }

        // Prover's active encodings are based on their choice bits.
        let active_encodings = choose(&full_encodings, &plaintext.to_msb0_vec());

        // Prover creates two commitments: to the front and to the tail portions of the plaintext.
        // Some middle bits of the plaintext will not be committed to.
        let range1 = 0..PLAINTEXT_SIZE / 2 - 10;
        let range2 = PLAINTEXT_SIZE / 2..PLAINTEXT_SIZE;

        let bit_ids1 = MockBitIds::new(Direction::Sent, vec![range1.clone()]);
        let bit_ids2 = MockBitIds::new(Direction::Sent, vec![range2.clone()]);

        let commitment1 = CommitmentData::new(
            plaintext[range1.clone()].to_vec(),
            active_encodings[range1.clone().start * 8..range1.clone().end * 8].to_vec(),
            bit_ids1,
        );
        let commitment2 = CommitmentData::new(
            plaintext[range2.clone()].to_vec(),
            active_encodings[range2.clone().start * 8..range2.clone().end * 8].to_vec(),
            bit_ids2,
        );

        let (prover, commitments) = prover.commit(vec![commitment1, commitment2]).unwrap();
        let commitments = bincode::serialize(&commitments).unwrap();

        // The Verifier receives the commitments.
        let commitments = bincode::deserialize(&commitments).unwrap();
        let all_bit_ids = MockBitIds::new(Direction::Sent, vec![0..PLAINTEXT_SIZE]);
        let full_encodings = FullEncodings::new_from_bytes(full_encodings.to_vec(), all_bit_ids);

        let verifier = verifier
            .receive_commitments(
                commitments,
                MockEncodingProvider::new(full_encodings.clone()),
            )
            .unwrap();

        // An encoding provider is instantiated with authenticated full encodings from external context.
        let (prover, proofs) = prover
            .prove(MockEncodingProvider::new(full_encodings.clone()))
            .unwrap();

        // The verifier verifies the proofs.
        let verifier = verifier.verify(proofs).unwrap();

        (prover, verifier)
    }

    pub trait BackendAsAny<F>: ProverBackend<F> + AsAny
    where
        F: Field,
    {
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

            fn commit_encoding_sum(
                &self,
                encoding_sum: F,
            ) -> Result<(F, F), crate::prover::error::ProverError> {
                self.prover.commit_encoding_sum(encoding_sum)
            }

            fn commit_plaintext(
                &self,
                plaintext: Vec<u8>,
            ) -> Result<(F, F), crate::prover::error::ProverError> {
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
        let (prover, _) = run_authdecode((prover_wrapper, verifier_wrapper));

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