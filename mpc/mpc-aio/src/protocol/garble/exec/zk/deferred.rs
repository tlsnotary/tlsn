//! This module contains `DeferredProver` and `DeferredVerifier` which are used to defer finalization of the proof
//! to another context via channels. This is useful when multiple proofs are required which use the same private inputs
//! from the Verifier. These types still ensure that the Prover is committed to the circuit output prior to deferral.
//!
//! ** CAUTION **
//!
//! Caution must be exercised when using these types! Users must understand the consequences of deferring the proof
//! verification when composed with other protocols.

use async_trait::async_trait;
use futures::{sink::Sink, SinkExt};

use mpc_circuits::{Input, InputValue, OutputValue};
use mpc_core::{
    garble::{
        exec::zk::{ProverSummary, VerifierSummary},
        ActiveEncodedInput, FullEncodedInput, FullInputSet,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::factory::AsyncFactory;

use crate::protocol::{
    garble::{
        exec::zk::{prover_state, verifier_state, Prove, Prover, Verifier, Verify},
        Compressor, Evaluator, GCError, Generator, Validator,
    },
    ot::{OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify},
};

/// A `DeferredProver` is a `Prover` which defers finalization of the proof to another context via a `Sink`.
pub struct DeferredProver<S, B, LRF, LR>
where
    B: Evaluator + Compressor + Validator,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError>,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput>,
{
    prover: Prover<prover_state::Initialized, B, LRF, LR>,
    sink: S,
}

impl<S, B, LRF, LR> DeferredProver<S, B, LRF, LR>
where
    S: Sink<Prover<prover_state::Validate, B, LRF, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new `DeferredProver` from a `Prover` and a `Sink`.
    pub fn new(prover: Prover<prover_state::Initialized, B, LRF, LR>, sink: S) -> Self {
        Self { prover, sink }
    }
}

#[async_trait]
impl<S, B, LRF, LR> Prove for DeferredProver<S, B, LRF, LR>
where
    S: Sink<Prover<prover_state::Validate, B, LRF, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    async fn prove(
        mut self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(), GCError> {
        _ = self.prove_and_summarize(inputs, cached_labels).await?;

        Ok(())
    }

    async fn prove_and_summarize(
        mut self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<ProverSummary, GCError> {
        let (summary, prover) = self
            .prover
            .setup_inputs(inputs, cached_labels)
            .await?
            .evaluate()
            .await?;

        self.sink
            .send(prover)
            .await
            .map_err(|e| GCError::DeferralError(e.to_string()))?;

        Ok(summary)
    }
}

/// A `DeferredVerifier` is a `Verifier` which defers finalization of the proof to another context via a `Sink`.
pub struct DeferredVerifier<S, B, LSF, LS>
where
    B: Generator + Compressor + Validator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    verifier: Verifier<verifier_state::Initialized, B, LSF, LS>,
    sink: S,
}

impl<S, B, LSF, LS> DeferredVerifier<S, B, LSF, LS>
where
    S: Sink<Verifier<verifier_state::Verify, B, LSF, LS>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Compressor + Validator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Create a new `DeferredVerifier` from a `Verifier` and a `Sink`.
    pub fn new(verifier: Verifier<verifier_state::Initialized, B, LSF, LS>, sink: S) -> Self {
        Self { verifier, sink }
    }
}

#[async_trait]
impl<S, B, LSF, LS> Verify for DeferredVerifier<S, B, LSF, LS>
where
    S: Sink<Verifier<verifier_state::Verify, B, LSF, LS>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Compressor + Validator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    async fn verify(
        mut self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<(), GCError> {
        _ = self
            .verify_and_summarize(gen_labels, inputs, ot_send_inputs, expected_output)
            .await?;

        Ok(())
    }

    async fn verify_and_summarize(
        mut self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<VerifierSummary, GCError> {
        let (summary, verifier) = self
            .verifier
            .setup_inputs(gen_labels, inputs, ot_send_inputs, expected_output)
            .await?
            .garble()
            .await?;

        self.sink
            .send(verifier)
            .await
            .map_err(|e| GCError::DeferralError(e.to_string()))?;

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::{channel::mpsc::channel, StreamExt};

    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_core::garble::exec::zk::{ProverConfigBuilder, VerifierConfigBuilder};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::protocol::garble::exec::zk::mock::create_mock_zk_pair;

    #[tokio::test]
    async fn test_deferred_zk() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(ADDER_64).unwrap();

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

        let (prover, verifier) = create_mock_zk_pair(prover_config, verifier_config);

        let (prover_sink, mut prover_stream) = channel(1);
        let (verifier_sink, mut verifier_stream) = channel(1);

        let deferred_prover = DeferredProver::new(prover, prover_sink);
        let deferred_verifier = DeferredVerifier::new(verifier, verifier_sink);

        let full_input_set = FullInputSet::generate(&mut rng, &circ, None);

        tokio::join!(
            async {
                deferred_prover
                    .prove(vec![circ.input(0).unwrap().to_value(1u64).unwrap()], vec![])
                    .await
                    .unwrap()
            },
            async {
                deferred_verifier
                    .verify(
                        full_input_set,
                        vec![circ.input(1).unwrap().to_value(1u64).unwrap()],
                        vec![circ.input(0).unwrap()],
                        vec![circ.output(0).unwrap().to_value(2u64).unwrap()],
                    )
                    .await
                    .unwrap()
            }
        );

        let prover = prover_stream.next().await.unwrap();
        let verifier = verifier_stream.next().await.unwrap();

        tokio::join!(async { prover.prove().await.unwrap() }, async {
            verifier.verify().await.unwrap()
        });
    }
}
