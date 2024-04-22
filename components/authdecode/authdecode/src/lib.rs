//! Copy-paste authdecode overview from the core crait.

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
        prover::{commitment::CommitmentData, state::ProofGenerated},
        verifier::state::VerifiedSuccessfully,
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
            authdecode_core::backend::halo2::fixtures::backend_pair(),
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
            .commit(&mut prover_sink, &commitment_data)
            .await
            .unwrap();

        let verifier = verifier
            .receive_commitments(&mut verifier_stream, encoding_provider.clone())
            .await
            .unwrap();

        // An encoding provider is instantiated with authenticated full encodings from external context.
        let prover = prover
            .prove(&mut prover_sink, encoding_provider)
            .await
            .unwrap();

        let verifier = verifier.verify(&mut verifier_stream).await.unwrap();

        (prover, verifier)
    }
}
