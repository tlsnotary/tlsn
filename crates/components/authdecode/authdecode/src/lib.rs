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

mod prover;
mod verifier;

pub use prover::Prover;
pub use verifier::Verifier;

#[cfg(test)]
mod tests {
    use crate::*;

    use authdecode_core::{
        backend::traits::{Field, ProverBackend, VerifierBackend},
        fixtures,
        mock::{MockBitIds, MockEncodingProvider},
        prover::{CommitmentData, ProofGenerated},
        verifier::VerifiedSuccessfully,
    };
    use futures_util::StreamExt;
    use rstest::*;
    use serde::{de::DeserializeOwned, Serialize};
    use std::ops::{Add, Sub};
    use utils_aio::duplex::MemoryDuplex;

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
    #[tokio::test]
    async fn test_mock_backend(
        commitment_data: Vec<CommitmentData<MockBitIds>>,
        encoding_provider: MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            authdecode_core::backend::mock::backend_pair(),
            commitment_data,
            encoding_provider,
        )
        .await;
    }

    // Tests the protocol with a halo2 backend.
    #[rstest]
    #[tokio::test]
    async fn test_halo2_backend(
        commitment_data: Vec<CommitmentData<MockBitIds>>,
        encoding_provider: MockEncodingProvider<MockBitIds>,
    ) {
        run_authdecode(
            authdecode_core::backend::halo2::fixtures::backend_pair_mock(),
            commitment_data,
            encoding_provider,
        )
        .await;
    }

    // Runs the protocol with the given backends.
    // Returns the prover and the verifier in their finalized state.
    #[allow(clippy::type_complexity)]
    async fn run_authdecode<F>(
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
        F: Field
            + Add<Output = F>
            + Sub<Output = F>
            + Serialize
            + DeserializeOwned
            + Clone
            + Send
            + 'static,
    {
        let prover = Prover::new(Box::new(pair.0));
        let verifier = Verifier::new(Box::new(pair.1));

        let (prover_channel, verifier_channel) = MemoryDuplex::new();

        let (mut prover_sink, _) = prover_channel.split();
        let (_, mut verifier_stream) = verifier_channel.split();

        let prover = prover
            .commit(&mut prover_sink, commitment_data)
            .await
            .unwrap();

        let verifier = verifier
            .receive_commitments(&mut verifier_stream)
            .await
            .unwrap();

        // An encoding provider is instantiated with authenticated full encodings from an external context.
        let prover = prover
            .prove(&mut prover_sink, &encoding_provider)
            .await
            .unwrap();

        let verifier = verifier
            .verify(&mut verifier_stream, &encoding_provider)
            .await
            .unwrap();

        (prover, verifier)
    }
}
