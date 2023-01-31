use std::{marker::PhantomData, sync::Arc};

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue};
use mpc_core::{
    garble::{
        exec::deap::{self as core, DEAPConfig},
        gc_state, ActiveEncodedInput, ActiveInputSet, FullEncodedInput, FullInputSet,
        GarbledCircuit,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

use super::{setup_inputs_with, DEAPExecute, DEAPVerify};

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl<LS> Sealed for super::LabelSetup<LS> {}
        impl<LS> Sealed for super::Executed<LS> {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup<LS> {
        pub(crate) gen_labels: FullInputSet,
        pub(crate) ev_labels: ActiveInputSet,
        pub(crate) label_sender: Option<LS>,
    }

    pub struct Executed<LS> {
        pub(super) core: core::DEAPFollower<core::follower_state::Open>,
        pub(crate) label_sender: Option<LS>,
    }

    impl State for Initialized {}
    impl<LS> State for LabelSetup<LS> {}
    impl<LS> State for Executed<LS> {}
}

use state::*;

pub struct DEAPFollower<S, B, LSF, LRF, LS, LR>
where
    S: State,
{
    config: DEAPConfig,
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,

    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<B, LSF, LRF, LS, LR> DEAPFollower<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    pub fn new(
        config: DEAPConfig,
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> Self {
        DEAPFollower {
            config,
            state: Initialized,
            circ,
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
    /// * `gen_labels` - Labels to garble the follower's circuit
    /// * `gen_inputs` - Inputs for which the labels are to be sent directly to the leader
    /// * `ot_send_inputs` - Inputs for which the labels are to be sent via OT
    /// * `ot_receive_inputs` - Inputs for which the labels are to be received via OT
    /// * `cached_labels` - Cached input labels for the leader's circuit.
    ///                     These can be both the leader's and follower's labels.
    pub async fn setup_inputs(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<DEAPFollower<LabelSetup<LS>, B, LSF, LRF, LS, LR>, GCError> {
        let label_sender_id = format!("{}/ot/1", self.config.id());
        let label_receiver_id = format!("{}/ot/0", self.config.id());

        let ((gen_labels, ev_labels), (label_sender, _)) = setup_inputs_with(
            label_sender_id,
            label_receiver_id,
            &mut self.channel,
            &mut self.label_sender_factory,
            &mut self.label_receiver_factory,
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

        Ok(DEAPFollower {
            config: self.config,
            state: LabelSetup {
                gen_labels,
                ev_labels,
                label_sender,
            },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender_factory: self.label_sender_factory,
            label_receiver_factory: self.label_receiver_factory,

            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        })
    }
}

impl<B, LSF, LRF, LS, LR> DEAPFollower<LabelSetup<LS>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Execute first phase of the protocol, returning the _purported_ circuit output.
    ///
    /// The output returned from this function can not be considered authentic until it is
    /// validated in the next phase.
    pub async fn execute(
        self,
    ) -> Result<
        (
            Vec<OutputValue>,
            DEAPFollower<Executed<LS>, B, LSF, LRF, LS, LR>,
        ),
        GCError,
    > {
        // Discard the summary
        let (output, _, follower) = self.execute_and_summarize().await?;
        Ok((output, follower))
    }

    /// Execute first phase of the protocol, returning the _purported_ circuit output and
    /// a summary of the leader's garbled circuit.
    ///
    /// The output returned from this function can not be considered authentic until it is
    /// validated in the next phase.
    pub async fn execute_and_summarize(
        mut self,
    ) -> Result<
        (
            Vec<OutputValue>,
            GarbledCircuit<gc_state::EvaluatedSummary>,
            DEAPFollower<Executed<LS>, B, LSF, LRF, LS, LR>,
        ),
        GCError,
    > {
        let follower = core::DEAPFollower::new(self.circ.clone());

        // Garble circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(full_gc)?;

        // Send garbled circuit to leader
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Receive leader's garbled circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        // Check their gc against circuit spec
        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        // Evaluate leader's garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        // Summarize the evaluated circuit
        let evaluated_summary = evaluated_gc.get_summary();

        // Decode purported output
        let (purported_output, follower) = follower.from_evaluated_circuit(evaluated_gc)?;

        // Receive output commitment to our circuit from leader
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::HashCommitment,
            GCError::Unexpected
        )?;

        let leader_commit = msg.into();

        // Reveal output of leader's garbled circuit to leader
        let (output, follower) = follower.reveal(leader_commit);

        self.channel
            .send(GarbleMessage::Output(output.into()))
            .await?;

        Ok((
            purported_output,
            evaluated_summary,
            DEAPFollower {
                config: self.config,
                state: Executed {
                    core: follower,
                    label_sender: self.state.label_sender,
                },
                circ: self.circ,
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

#[async_trait]
impl<B, LSF, LRF, LS, LR> DEAPExecute for DEAPFollower<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send + 'static,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send + 'static,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send + 'static,
{
    type NextState = DEAPFollower<Executed<LS>, B, LSF, LRF, LS, LR>;

    async fn execute(
        self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(Vec<OutputValue>, Self::NextState), GCError> {
        self.setup_inputs(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?
        .execute()
        .await
    }

    async fn execute_and_summarize(
        self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<
        (
            Vec<OutputValue>,
            GarbledCircuit<gc_state::EvaluatedSummary>,
            Self::NextState,
        ),
        GCError,
    > {
        self.setup_inputs(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?
        .execute_and_summarize()
        .await
    }
}

impl<B, LSF, LRF, LS, LR> DEAPFollower<Executed<LS>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Execute the final phase of the protocol. This verifies the authenticity of the circuit output
    /// from the prior phase.
    ///
    /// **CAUTION**
    ///
    /// Calling this function reveals all of the follower's private inputs to the leader! Care must be taken
    /// to ensure that this is synchronized properly with any other uses of these inputs.
    pub async fn verify(mut self) -> Result<(), GCError> {
        let follower = self.state.core;

        // Open our circuit to leader
        let (opening, follower) = follower.open();

        self.channel
            .send(GarbleMessage::CircuitOpening(opening.into()))
            .await?;

        // Open our OTs to leader
        if let Some(label_sender) = self.state.label_sender.take() {
            label_sender.reveal().await?;
        }

        // Receive opening to output commitment
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CommitmentOpening,
            GCError::Unexpected
        )?;

        // Verify commitment and output to our circuit
        follower.verify(msg.into()).map_err(GCError::from)
    }
}

#[async_trait]
impl<B, LSF, LRF, LS, LR> DEAPVerify for DEAPFollower<Executed<LS>, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LSF: Send,
    LRF: Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    async fn verify(self) -> Result<(), GCError> {
        self.verify().await
    }

    async fn verify_boxed(self: Box<Self>) -> Result<(), GCError> {
        self.verify().await
    }
}
