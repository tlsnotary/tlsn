use std::sync::Arc;

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{ObliviousReceive, ObliviousReveal, ObliviousSend},
};
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, InputValue, OutputValue, WireGroup};
use mpc_core::garble::{
    exec::deap as core, gc_state, ActiveInputLabels, Delta, FullInputLabels, GarbledCircuit,
};
use utils_aio::expect_msg_or_err;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Executed {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct Executed {
        pub(super) core: core::DEAPFollower<core::follower_state::Open>,
    }

    impl State for Initialized {}
    impl State for Executed {}
}

use state::*;

pub struct DEAPFollower<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullInputLabels> + ObliviousReveal,
    LR: ObliviousReceive<InputValue, ActiveInputLabels>,
{
    state: S,
    channel: GarbleChannel,
    backend: B,
    label_sender: LS,
    label_receiver: LR,
}

impl<B, LS, LR> DEAPFollower<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullInputLabels> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub fn new(channel: GarbleChannel, backend: B, label_sender: LS, label_receiver: LR) -> Self {
        DEAPFollower {
            state: Initialized,
            channel,
            backend,
            label_sender,
            label_receiver,
        }
    }

    /// Execute first phase of the protocol, returning the _purported_ circuit output.
    /// This output can not be considered authentic and is not validated until the next phase.
    ///
    /// * `circ` - Circuit to execute
    /// * `inputs` - Follower's input to the circuit
    /// * `input_labels` - Input labels used to garble follower's circuit
    /// * `delta` - Delta used to garble follower's circuit
    pub async fn execute(
        mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<(Vec<OutputValue>, DEAPFollower<Executed, B, LS, LR>), GCError> {
        let follower = core::DEAPFollower::new(circ.clone());

        // Garble circuit
        let full_gc = self
            .backend
            .generate(circ.clone(), delta, &input_labels)
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(inputs, full_gc)?;

        // Send garbled circuit to leader
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Send leader their active labels
        let follower_input_ids = inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();
        let leader_labels = input_labels
            .iter()
            .filter(|input| !follower_input_ids.contains(&input.id()))
            .cloned()
            .collect::<Vec<FullInputLabels>>();

        self.label_sender.send(leader_labels).await?;

        // Receive leader's garbled circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        // Check their gc against circuit spec
        let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;

        // Retrieve active labels to leader's circuit
        let labels_ev = self.label_receiver.receive(inputs.to_vec()).await?;

        // Evaluate leader's garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, &labels_ev).await?;

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
            DEAPFollower {
                state: Executed { core: follower },
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
    LS: ObliviousSend<FullInputLabels> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
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
        self.label_sender.reveal().await?;

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
