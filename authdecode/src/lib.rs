//! Implementation of the AuthDecode protocol.
//! The protocol performs authenticated decoding of encodings in zero knowledge.
//!
//! The purpose of AuthDecode is to allow the GC evaluator to produce a zk-friendly
//! hash commitment to the GC output. Computing a zk-friendly hash directly inside
//! the GC is too expensive, hence the need for this protocol.
//!
//! The high-level overview of Authdecode is:
//! - The Verifier first reveals all of his secret inputs to the GC
//! - The Prover computes the expected output of GC ("the plaintext") in the
//! clear and commits to it
//! - The Verifier sends the GC but withholds the output decoding information
//! - The Prover evaluates the circuit and commits to his active output labels
//! - The Verifier reveals all the output labels of the circuit
//! - The Prover, without revealing the plaintext, creates a zero-knowledge proof
//! that the plaintext he committed to earlier is the true output of the GC evaluation
//!
//! Authdecode assumes a privacy-free setting for the garbler, i.e. the protocol
//! MUST ONLY start AFTER the garbler reveals all his secret GC inputs.
//! Specifically, in the context of the TLSNotary protocol, AuthDecode MUST ONLY
//! start AFTER the Notary (who is the garbler) has revealed all of his TLS session
//! keys' shares.
//!
//! See ../authdecode_diagram.pdf for a diagram of the whole protocol

#[allow(unused_imports)]
pub mod backend;
pub mod encodings;
pub mod prover;
pub mod utils;
pub mod verifier;

use crate::prover::prover::ProofInput;
use num::BigInt;

/// An arithmetic difference between the arithmetic label "one" and the
/// arithmetic label "zero".
type Delta = BigInt;

/// An opaque proof of the AuthDecode circuit.
type Proof = Vec<u8>;

/// A zk proof with the corresponding public inputs.
struct ProofProperties {
    proof: Proof,
    public_inputs: ProofInput,
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::{
            halo2,
            halo2::{
                prover::Prover as Halo2ProverBackend, verifier::Verifier as Halo2VerififerBackend,
            },
            mock::{MockProverBackend, MockVerifierBackend},
        },
        encodings::{ActiveEncodings, Encoding, FullEncodings, ToActiveEncodings},
        prover::{
            backend::Backend as ProverBackend,
            error::ProverError,
            prover::{ProofInput, Prover},
            InitData, ToInitData,
        },
        utils::{choose, u8vec_to_boolvec},
        verifier::{backend::Backend as VerifierBackend, verifier::Verifier},
        Proof,
    };

    use hex::encode;
    use num::BigUint;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::rstest;

    /// The size of plaintext in bytes;
    const PLAINTEXT_SIZE: usize = 1000;

    // A dummy encodings verifier.
    struct DummyEncodingsVerifier {}
    impl crate::prover::EncodingVerifier for DummyEncodingsVerifier {
        fn init(&self, init_data: InitData) {}

        fn verify(
            &self,
            _encodings: &FullEncodings,
        ) -> Result<(), crate::prover::EncodingVerifierError> {
            Ok(())
        }
    }

    #[rstest]
    #[case(crate::backend::mock::tests::backend_pair())]
    #[case(crate::backend::halo2::tests::backend_pair())]
    // Test the protocol with different
    fn test_authdecode(
        #[case] pair: (impl ProverBackend + 'static, impl VerifierBackend + 'static),
    ) {
        let prover = Prover::new(Box::new(pair.0));
        let verifier = Verifier::new(Box::new(pair.1));

        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Generate random plaintext.
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(PLAINTEXT_SIZE)
            .collect();

        // Generate Verifier's full encodings for each bit of the plaintext.
        let full_encodings: Vec<[u128; 2]> = core::iter::repeat_with(|| rng.gen::<[u128; 2]>())
            .take(PLAINTEXT_SIZE * 8)
            .collect();
        let full_encodings = full_encodings
            .into_iter()
            .map(|pair| {
                [
                    Encoding::new(BigUint::from(pair[0])),
                    Encoding::new(BigUint::from(pair[1])),
                ]
            })
            .collect::<Vec<_>>();
        let full_encodings = FullEncodings::new(full_encodings);

        // Prover's active encodings.
        let active_encodings = full_encodings.encode(&u8vec_to_boolvec(&plaintext));

        let (prover, commitments) = prover.commit(vec![(plaintext, active_encodings)]).unwrap();

        let (verifier, verification_data) = verifier
            .receive_commitments(
                commitments,
                vec![full_encodings.clone()],
                InitData::new(vec![1u8; 100]),
            )
            .unwrap();

        let prover = prover
            .check(verification_data, DummyEncodingsVerifier {})
            .unwrap();

        let (prover, proof_sets) = prover.prove().unwrap();

        let verifier = verifier.verify(proof_sets).unwrap();
    }
}
