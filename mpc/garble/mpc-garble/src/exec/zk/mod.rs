//! An implementation of malicious-secure zero-knowledge proofs using Garbled Circuits.
//!
//! This protocol allows a Prover to prove in zero-knowledge the output of a circuit to a Verifier
//! without leaking any information about their private inputs. The Verifier can also provide
//! private inputs which are revealed after the Prover commits to the output of the circuit.
//!
//! # Overview
//!
//! The protocol is based on the [JKO13](https://eprint.iacr.org/2013/073.pdf) and it goes as follows:
//!
//! 1. The Verifier acts as the garbled circuit Generator, sending it to the Prover.
//! 2. The Prover evaluates the garbled circuit and commits to the output.
//! 3. The Verifier opens the garbled circuit to the Prover, revealing all of their private inputs.
//! 4. The Prover verifies the authenticity of the garbled circuit and oblivious transfers.
//! 5. If the garbled circuit is authentic, the Prover opens the output commitment to the Verifier.
//! 6. The Verifier verifies the output and output commitment.

mod deferred;
mod prover;
mod verifier;

pub use deferred::{DeferredProver, DeferredVerifier};
pub use prover::{state as prover_state, Prover};
pub use verifier::{state as verifier_state, Verifier};

use async_trait::async_trait;

use mpc_circuits::{Input, InputValue, OutputValue};
use mpc_garble_core::{
    exec::zk::{ProverSummary, VerifierSummary},
    ActiveEncodedInput, FullInputSet,
};

use crate::GCError;

/// This trait facilitates proving the output of a circuit in
/// zero-knowledge.
#[async_trait]
pub trait Prove {
    /// Proves the output of a circuit to a Verifier.
    ///
    /// * `inputs` - The Prover's private inputs to the circuit.
    /// * `cached_labels` - Cached labels for the circuit's inputs.
    async fn prove(
        self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(), GCError>;

    /// Proves the output of a circuit to a Verifier, returning
    /// a summary of the proof.
    ///
    /// * `inputs` - The Prover's private inputs to the circuit.
    /// * `cached_labels` - Cached labels for the circuit's inputs.
    async fn prove_and_summarize(
        self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<ProverSummary, GCError>;
}

/// This trait facilitates verifying the output of a circuit in
/// zero-knowledge.
#[async_trait]
pub trait Verify {
    /// Verifies the authenticity of a circuit output evaluated by a Prover.
    ///
    /// **CAUTION**
    ///
    /// Calling this function will reveal all of the Verifier's private inputs to the Prover!
    /// Care must be taken to ensure that this is synchronized properly with any other uses of these inputs.
    ///
    /// * `gen_labels` - The labels used to garble the circuit.
    /// * `inputs` - The Verifier's private inputs to the circuit.
    /// * `ot_send_inputs` - The inputs which are to be sent to the Prover via OT.
    /// * `expected_output` - The expected output of the circuit.
    async fn verify(
        self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<(), GCError>;

    /// Verifies the authenticity of a circuit output evaluated by a Prover, returning
    /// a summary of the proof.
    ///
    /// **CAUTION**
    ///
    /// Calling this function will reveal all of the Verifier's private inputs to the Prover!
    /// Care must be taken to ensure that this is synchronized properly with any other uses of these inputs.
    ///
    /// * `gen_labels` - The labels used to garble the circuit.
    /// * `inputs` - The Verifier's private inputs to the circuit.
    /// * `ot_send_inputs` - The inputs which are to be sent to the Prover via OT.
    /// * `expected_output` - The expected output of the circuit.
    async fn verify_and_summarize(
        self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<VerifierSummary, GCError>;
}

#[cfg(feature = "mock")]
pub mod mock {
    use mpc_core::Block;
    use mpc_garble_core::exec::zk::{ProverConfig, VerifierConfig};
    use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use utils_aio::duplex::DuplexChannel;

    use crate::backend::RayonBackend;

    use super::*;

    pub type MockProver = Prover<
        prover_state::Initialized,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTReceiver<Block>,
    >;
    pub type MockVerifier = Verifier<
        verifier_state::Initialized,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTSender<Block>,
    >;

    pub fn create_mock_zk_pair(
        prover_config: ProverConfig,
        verifier_config: VerifierConfig,
    ) -> (MockProver, MockVerifier) {
        let (prover_channel, verifier_channel) = DuplexChannel::new();
        let ot_factory = MockOTFactory::<Block>::new();
        let prover = Prover::new(
            prover_config,
            Box::new(prover_channel),
            RayonBackend,
            ot_factory.clone(),
        );
        let verifier = Verifier::new(
            verifier_config,
            Box::new(verifier_channel),
            RayonBackend,
            ot_factory,
        );
        (prover, verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use std::sync::Arc;

    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_garble_core::{
        exec::zk::{ProverConfigBuilder, VerifierConfigBuilder},
        FullInputSet,
    };

    #[fixture]
    fn circ() -> Arc<Circuit> {
        ADDER_64.clone()
    }

    #[rstest]
    #[tokio::test]
    async fn test_zk_both_inputs(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let prover_config = ProverConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let verifier_config = VerifierConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let (prover, verifier) = mock::create_mock_zk_pair(prover_config, verifier_config);

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let prover_fut = {
            let circ = circ.clone();
            async move {
                prover
                    .prove(vec![circ.input(0).unwrap().to_value(1u64).unwrap()], vec![])
                    .await
                    .unwrap();
            }
        };

        let verifier_fut = async move {
            verifier
                .verify(
                    full_input_set,
                    vec![circ.input(1).unwrap().to_value(1u64).unwrap()],
                    vec![circ.input(0).unwrap()],
                    vec![circ.output(0).unwrap().to_value(2u64).unwrap()],
                )
                .await
                .unwrap()
        };

        futures::join!(prover_fut, verifier_fut);
    }

    #[rstest]
    #[tokio::test]
    async fn test_zk_prover_inputs(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let prover_config = ProverConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let verifier_config = VerifierConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let (prover, verifier) = mock::create_mock_zk_pair(prover_config, verifier_config);

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let prover_fut = {
            let circ = circ.clone();
            async move {
                prover
                    .prove(
                        vec![
                            circ.input(0).unwrap().to_value(1u64).unwrap(),
                            circ.input(1).unwrap().to_value(1u64).unwrap(),
                        ],
                        vec![],
                    )
                    .await
                    .unwrap()
            }
        };

        let verifier_fut = async move {
            verifier
                .verify(
                    full_input_set,
                    vec![],
                    vec![circ.input(0).unwrap(), circ.input(1).unwrap()],
                    vec![circ.output(0).unwrap().to_value(2u64).unwrap()],
                )
                .await
                .unwrap()
        };

        futures::join!(prover_fut, verifier_fut);
    }

    #[rstest]
    #[tokio::test]
    async fn test_zk_proof_error(circ: Arc<Circuit>) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let prover_config = ProverConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let verifier_config = VerifierConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let (prover, verifier) = mock::create_mock_zk_pair(prover_config, verifier_config);

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        let prover_fut = {
            let circ = circ.clone();
            async move {
                prover
                    .prove(vec![circ.input(0).unwrap().to_value(1u64).unwrap()], vec![])
                    .await
                    .unwrap();
            }
        };

        let verifier_fut = async move {
            verifier
                .verify(
                    full_input_set,
                    vec![circ.input(1).unwrap().to_value(1u64).unwrap()],
                    vec![circ.input(0).unwrap()],
                    // expect a different output
                    vec![circ.output(0).unwrap().to_value(3u64).unwrap()],
                )
                .await
                .unwrap_err()
        };

        let (_, err) = futures::join!(prover_fut, verifier_fut);

        assert!(matches!(err, GCError::ProofError(_)));
    }
}
