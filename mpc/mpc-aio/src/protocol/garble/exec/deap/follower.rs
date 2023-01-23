use std::sync::Arc;

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{ObliviousReceive, ObliviousReveal, ObliviousSend},
};
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue};
use mpc_core::garble::{
    exec::deap as core, gc_state, ActiveEncodedInput, ActiveInputSet, FullEncodedInput,
    FullInputSet, GarbledCircuit,
};
use utils_aio::expect_msg_or_err;

use super::setup_inputs_with;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::LabelSetup {}
        impl Sealed for super::Executed {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup {
        pub(crate) gen_labels: FullInputSet,
        pub(crate) ev_labels: ActiveInputSet,
    }

    pub struct Executed {
        pub(super) core: core::DEAPFollower<core::follower_state::Open>,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
    impl State for Executed {}
}

use state::*;

pub struct DEAPFollower<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: Option<LS>,
    label_receiver: Option<LR>,
}

impl<B, LS, LR> DEAPFollower<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: Option<LS>,
        label_receiver: Option<LR>,
    ) -> Self {
        DEAPFollower {
            state: Initialized,
            circ,
            channel,
            backend,
            label_sender,
            label_receiver,
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
    ) -> Result<DEAPFollower<LabelSetup, B, LS, LR>, GCError> {
        let (gen_labels, ev_labels) = setup_inputs_with(
            &mut self.channel,
            self.label_sender.as_mut(),
            self.label_receiver.as_mut(),
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

        Ok(DEAPFollower {
            state: LabelSetup {
                gen_labels,
                ev_labels,
            },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender: self.label_sender,
            label_receiver: self.label_receiver,
        })
    }
}

impl<B, LS, LR> DEAPFollower<LabelSetup, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Execute first phase of the protocol, returning the _purported_ circuit output.
    ///
    /// The output returned from this function can not be considered authentic until it is
    /// validated in the next phase.
    pub async fn execute(
        self,
    ) -> Result<(Vec<OutputValue>, DEAPFollower<Executed, B, LS, LR>), GCError> {
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
            DEAPFollower<Executed, B, LS, LR>,
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
                state: Executed { core: follower },
                circ: self.circ,
                channel: self.channel,
                backend: self.backend,
                label_sender: self.label_sender,
                label_receiver: self.label_receiver,
            },
        ))
    }
}

impl<B, LS, LR> DEAPFollower<Executed, B, LS, LR>
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
        if let Some(label_sender) = self.label_sender.take() {
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
