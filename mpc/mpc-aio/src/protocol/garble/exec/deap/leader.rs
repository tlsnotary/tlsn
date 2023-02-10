use std::marker::PhantomData;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};

use crate::protocol::{
    garble::{
        exec::dual::DEExecute, Compressor, Evaluator, GCError, GarbleChannel, GarbleMessage,
        Generator, Validator,
    },
    ot::{OTFactoryError, ObliviousReceive, ObliviousSend, ObliviousVerify},
};
use mpc_circuits::{Input, InputValue, OutputValue, WireGroup};
use mpc_core::{
    garble::{
        exec::{
            deap as core,
            dual::{DESummary, DualExConfig},
        },
        gc_state, ActiveEncodedInput, ActiveInputSet, FullEncodedInput, FullInputSet,
        GarbledCircuit,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

use super::setup_inputs_with;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl<LR> Sealed for super::LabelSetup<LR> {}
        impl<LR> Sealed for super::Executed<LR> {}
        impl<LR> Sealed for super::EqualityCheck<LR> {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup<LR> {
        pub(crate) gen_labels: FullInputSet,
        pub(crate) ev_labels: ActiveInputSet,
        pub(crate) input_state: InputState,
        pub(crate) label_receiver: Option<LR>,
    }

    pub struct Executed<LR> {
        pub(crate) core: core::DEAPLeader<core::leader_state::Commit>,
        pub(crate) input_state: InputState,
        pub(crate) label_receiver: Option<LR>,
    }

    pub struct EqualityCheck<LR> {
        pub(crate) core: core::DEAPLeader<core::leader_state::Validate>,
        pub(crate) input_state: InputState,
        pub(crate) label_receiver: Option<LR>,
    }

    impl State for Initialized {}
    impl<LR> State for LabelSetup<LR> {}
    impl<LR> State for Executed<LR> {}
    impl<LR> State for EqualityCheck<LR> {}

    pub(crate) struct InputState {
        pub(crate) ot_receive_inputs: Vec<Input>,
    }
}

use state::*;

pub struct DEAPLeader<S, B, LSF, LRF, LS, LR>
where
    S: State,
{
    config: DualExConfig,
    state: S,
    channel: GarbleChannel,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,

    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<B, LSF, LRF, LS, LR> DEAPLeader<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    pub fn new(
        config: DualExConfig,
        channel: GarbleChannel,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> DEAPLeader<Initialized, B, LSF, LRF, LS, LR> {
        DEAPLeader {
            config,
            state: Initialized,
            channel,
            backend,
            label_sender_factory,
            label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        }
    }

    /// Exchange input labels
    ///
    /// * `gen_labels` - Labels to garble the leader's circuit
    /// * `gen_inputs` - Inputs for which the labels are to be sent directly to the follower
    /// * `ot_send_inputs` - Inputs for which the labels are to be sent via OT
    /// * `ot_receive_inputs` - Inputs for which the labels are to be received via OT
    /// * `cached_labels` - Cached input labels for the follower's circuit.
    ///                     These can be both the leader's and follower's labels.
    pub async fn setup_inputs(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<DEAPLeader<LabelSetup<LR>, B, LSF, LRF, LS, LR>, GCError> {
        let label_sender_id = format!("{}/ot/0", self.config.id());
        let label_receiver_id = format!("{}/ot/1", self.config.id());

        let ((gen_labels, ev_labels), (_, label_receiver)) = setup_inputs_with(
            label_sender_id,
            label_receiver_id,
            &mut self.channel,
            &mut self.label_sender_factory,
            &mut self.label_receiver_factory,
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs.clone(),
            cached_labels,
        )
        .await?;

        Ok(DEAPLeader {
            config: self.config,
            state: LabelSetup {
                gen_labels,
                ev_labels,
                input_state: InputState {
                    ot_receive_inputs: ot_receive_inputs
                        .into_iter()
                        .map(|v| v.group().clone())
                        .collect(),
                },
                label_receiver,
            },
            channel: self.channel,
            backend: self.backend,
            label_sender_factory: self.label_sender_factory,
            label_receiver_factory: self.label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        })
    }
}

impl<B, LSF, LRF, LS, LR> DEAPLeader<LabelSetup<LR>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Executes both garbled circuits, stopping prior to the equality check.
    ///
    /// Returns a summary of the exection.
    pub async fn execute_until_equality_check(
        mut self,
    ) -> Result<(DESummary, DEAPLeader<Executed<LR>, B, LSF, LRF, LS, LR>), GCError> {
        let leader = core::DEAPLeader::new(self.config.circ());

        // Garble circuit
        let full_gc = self
            .backend
            .generate(self.config.circ(), self.state.gen_labels)
            .await?;

        let full_gc_summary = full_gc.get_summary();

        let (partial_gc, leader) = leader.from_full_circuit(full_gc)?;

        // Send garbled circuit to follower
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Receive follower's garbled circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        // Check their gc against circuit spec
        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.config.circ(), msg.into())?;

        // Evaluate follower's garbled circuit
        let gc_evaluated = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        // Summarize follower's circuit to reduce memory footprint
        let gc_evaluated_summary = gc_evaluated.get_summary();

        // Also compress follower's circuit to reduce memory footprint before validating it in the next phase
        let gc_cmp = self.backend.compress(gc_evaluated).await?;

        let leader = leader.from_compressed_circuit(gc_cmp)?;

        let summary = DESummary::new(full_gc_summary, gc_evaluated_summary);

        Ok((
            summary,
            DEAPLeader {
                config: self.config,
                state: Executed {
                    core: leader,
                    input_state: self.state.input_state,
                    label_receiver: self.state.label_receiver,
                },
                channel: self.channel,
                backend: self.backend,
                label_sender_factory: self.label_sender_factory,
                label_receiver_factory: self.label_receiver_factory,
                _label_sender: PhantomData,
                _label_receiver: PhantomData,
            },
        ))
    }
}

impl<B, LSF, LRF, LS, LR> DEAPLeader<Executed<LR>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Start the equality check phase of the protocol, committing to the output and
    /// receiving the authentic output from the follower.
    ///
    /// Returns the authentic output of the circuit
    pub async fn start_equality_check(
        mut self,
    ) -> Result<
        (
            Vec<OutputValue>,
            DEAPLeader<EqualityCheck<LR>, B, LSF, LRF, LS, LR>,
        ),
        GCError,
    > {
        // Commit to equality check value
        let (commit, leader) = self.state.core.commit();

        self.channel
            .send(GarbleMessage::HashCommitment(commit.into()))
            .await?;

        // Receive output to our garbled circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::Output,
            GCError::Unexpected
        )?;

        // Validate output and decode
        let (output, leader) = leader.decode(msg.into())?;

        Ok((
            output,
            DEAPLeader {
                config: self.config,
                state: EqualityCheck {
                    core: leader,
                    input_state: self.state.input_state,
                    label_receiver: self.state.label_receiver,
                },
                channel: self.channel,
                backend: self.backend,
                label_sender_factory: self.label_sender_factory,
                label_receiver_factory: self.label_receiver_factory,
                _label_sender: PhantomData,
                _label_receiver: PhantomData,
            },
        ))
    }
}

impl<B, LSF, LRF, LS, LR> DEAPLeader<EqualityCheck<LR>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Execute the final phase of the protocol. This proves the authenticity of the circuit output
    /// to the follower without leaking any information about leader's inputs.
    pub async fn finalize_equality_check(mut self) -> Result<(), GCError> {
        let leader = self.state.core;

        // Receive circuit opening to follower's circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CircuitOpening,
            GCError::Unexpected
        )?;

        // Check circuit opening and pull it out for async validation
        let (opening, gc_cmp, leader) = leader.validate_external(msg.into())?;

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
                let Some(label_receiver) = self.state.label_receiver.take() else {
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

        // Reveal output to follower
        let commit_opening = leader.reveal();

        self.channel
            .send(GarbleMessage::CommitmentOpening(commit_opening.into()))
            .await?;

        Ok(())
    }
}

#[async_trait]
impl<B, LSF, LRF, LS, LR> DEExecute for DEAPLeader<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    async fn execute(
        self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<Vec<OutputValue>, GCError> {
        let (outputs, _) = self
            .execute_and_summarize(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        Ok(outputs)
    }

    async fn execute_and_summarize(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(Vec<OutputValue>, DESummary), GCError> {
        let (summary, follower) = self
            .setup_inputs(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?
            .execute_until_equality_check()
            .await?;

        let (output, follower) = follower.start_equality_check().await?;
        follower.finalize_equality_check().await?;

        Ok((output, summary))
    }

    async fn execute_skip_equality_check(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<DESummary, GCError> {
        let (summary, _) = self
            .setup_inputs(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?
            .execute_until_equality_check()
            .await?;

        Ok(summary)
    }
}
