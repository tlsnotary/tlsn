use crate::protocol::{
    garble::{Compressor, Evaluator, GCError, GarbleChannel, GarbleMessage, Validator},
    ot::{OTFactoryError, ObliviousReceive, ObliviousVerify},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{InputValue, WireGroup};
use mpc_core::{
    garble::{
        exec::zk::{self as zk_core, ProverConfig, ProverSummary},
        gc_state, ActiveEncodedInput, ActiveInputSet, FullEncodedInput, FullInputSet,
        GarbledCircuit,
    },
    ot::config::{OTReceiverConfig, OTReceiverConfigBuilder},
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

pub mod state {
    use mpc_circuits::Input;
    use mpc_core::garble::ActiveInputSet;

    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::LabelSetup {}
        impl Sealed for super::Validate {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup {
        pub(crate) labels: ActiveInputSet,
        pub(crate) input_state: InputState,
    }

    pub struct Validate {
        pub(crate) prover: zk_core::Prover<zk_core::prover_state::Validate>,
        pub(crate) input_state: InputState,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
    impl State for Validate {}

    pub(crate) struct InputState {
        pub(crate) ot_receive_inputs: Vec<Input>,
    }
}

use state::*;

pub struct Prover<S, B, LRF, LR>
where
    S: State,
    B: Evaluator + Compressor + Validator,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError>,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput>,
{
    config: ProverConfig,
    state: S,
    channel: GarbleChannel,
    backend: B,
    label_receiver_factory: LRF,
    label_receiver: Option<LR>,
}

impl<B, LRF, LR> Prover<Initialized, B, LRF, LR>
where
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new prover.
    pub fn new(
        config: ProverConfig,
        channel: GarbleChannel,
        backend: B,
        label_receiver_factory: LRF,
    ) -> Prover<Initialized, B, LRF, LR> {
        Self {
            config,
            state: Initialized,
            channel,
            backend,
            label_receiver_factory,
            label_receiver: None,
        }
    }

    /// Receive input labels
    ///
    /// * `ot_receive_inputs` - Inputs for which the labels are to be received via OT
    /// * `cached_labels` - Cached input labels
    pub async fn setup_inputs(
        mut self,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<Prover<LabelSetup, B, LRF, LR>, GCError> {
        let label_receiver_id = format!("{}/ot", self.config.id());
        let circ = self.config.circ();

        // If there are no labels to be received via OT, we can skip the OT protocol
        let ot_receive_fut = async {
            if ot_receive_inputs.len() > 0 {
                let count = ot_receive_inputs.iter().map(|input| input.len()).sum();

                let receiver_config = OTReceiverConfigBuilder::default()
                    .count(count)
                    .build()
                    .expect("OTReceiverConfig should be valid");

                let mut label_receiver = self
                    .label_receiver_factory
                    .create(label_receiver_id, receiver_config)
                    .await?;

                let ot_receive_labels = label_receiver.receive(ot_receive_inputs.clone()).await?;

                Result::<_, GCError>::Ok((ot_receive_labels, Some(label_receiver)))
            } else {
                Result::<_, GCError>::Ok((vec![], None))
            }
        };

        let direct_receive_fut = self.channel.next();

        let (ot_receive_result, direct_receive_result) =
            futures::future::join(ot_receive_fut, direct_receive_fut).await;

        let (ot_receive_labels, label_receiver) = ot_receive_result?;

        let msg = expect_msg_or_err!(
            direct_receive_result,
            GarbleMessage::InputLabels,
            GCError::Unexpected
        )?;

        let direct_received_labels = msg
            .into_iter()
            .map(|msg| ActiveEncodedInput::from_unchecked(&circ, msg.into()))
            .collect::<Result<Vec<_>, _>>()?;

        // Collect all active labels into a set
        let labels = ActiveInputSet::new(
            [ot_receive_labels, direct_received_labels, cached_labels].concat(),
        )?;

        Ok(Prover {
            config: self.config,
            state: LabelSetup {
                labels,
                input_state: InputState {
                    ot_receive_inputs: ot_receive_inputs
                        .into_iter()
                        .map(|v| v.group().clone())
                        .collect(),
                },
            },
            channel: self.channel,
            backend: self.backend,
            label_receiver_factory: self.label_receiver_factory,
            label_receiver,
        })
    }
}

impl<B, LRF, LR> Prover<LabelSetup, B, LRF, LR>
where
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Evaluate the garbled circuit and commit to the output
    pub async fn evaluate(
        mut self,
    ) -> Result<(ProverSummary, Prover<Validate, B, LRF, LR>), GCError> {
        let prover = zk_core::Prover::new(self.config.circ());

        // Expect garbled circuit from Verifier
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.config.circ(), msg.into())?;

        // Evaluate garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.labels).await?;

        let evaluator_summary = evaluated_gc.get_summary();

        let compressed_gc = self.backend.compress(evaluated_gc).await?;

        let (commitment, prover) = prover.from_compressed_circuit(compressed_gc).commit();

        // Send commitment
        self.channel
            .send(GarbleMessage::HashCommitment(commitment.into()))
            .await?;

        let summary = ProverSummary::new(evaluator_summary);

        Ok((
            summary,
            Prover {
                config: self.config,
                state: Validate {
                    prover,
                    input_state: self.state.input_state,
                },
                channel: self.channel,
                backend: self.backend,
                label_receiver_factory: self.label_receiver_factory,
                label_receiver: self.label_receiver,
            },
        ))
    }
}

impl<B, LRF, LR> Prover<Validate, B, LRF, LR>
where
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Execute the final phase of the protocol. This proves the authenticity of the circuit output
    /// to the Verifier without leaking any information about the Prover's inputs.
    pub async fn prove(mut self) -> Result<(), GCError> {
        // Receive circuit opening to verifier's circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CircuitOpening,
            GCError::Unexpected
        )?;

        // Check circuit opening and pull it out for async validation
        let (opening, gc_cmp, prover) = self.state.prover.validate_external(msg.into())?;

        // Reconstruct full input labels from opening
        let input_labels = FullInputSet::from_decoding(
            gc_cmp.input_labels().clone(),
            opening.get_delta(),
            opening.get_decoding().to_vec(),
        )?;

        // Concurrently validate OT and garbling
        let gc_validate_fut = self.backend.validate_compressed(gc_cmp, opening);

        // If we did not receive any inputs via OT, we can skip the OT validation
        let labels_validate_fut = async move {
            if self.state.input_state.ot_receive_inputs.is_empty() {
                Ok(())
            } else {
                let Some(label_receiver) = self.label_receiver.take() else {
                    return Err(GCError::MissingOTReceiver);
                };

                let ot_received = self
                    .state
                    .input_state
                    .ot_receive_inputs
                    .iter()
                    .map(|input| {
                        input_labels
                            .get(input.index())
                            .expect("Input id should be valid")
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                label_receiver
                    .verify(ot_received)
                    .await
                    .map_err(GCError::from)
            }
        };

        let (gc_validate_result, labels_validate_result) =
            futures::join!(gc_validate_fut, labels_validate_fut);

        // Both of these must pass to continue
        _ = gc_validate_result?;
        _ = labels_validate_result?;

        // Reveal output to verifier
        let (commit_opening, output) = prover.reveal();

        self.channel
            .feed(GarbleMessage::CommitmentOpening(commit_opening.into()))
            .await?;

        self.channel
            .send(GarbleMessage::Output(output.into()))
            .await?;

        Ok(())
    }
}

#[async_trait]
impl<B, LRF, LR> super::Prove for Prover<Initialized, B, LRF, LR>
where
    B: Evaluator + Compressor + Validator + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    async fn prove(
        self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(), GCError> {
        _ = self.prove_and_summarize(inputs, cached_labels).await?;

        Ok(())
    }

    async fn prove_and_summarize(
        self,
        inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<ProverSummary, GCError> {
        let (summary, prover) = self
            .setup_inputs(inputs, cached_labels)
            .await?
            .evaluate()
            .await?;

        prover.prove().await?;

        Ok(summary)
    }
}
