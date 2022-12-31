use std::sync::Arc;

use crate::protocol::{
    garble::{Compressor, Evaluator, GCError, GarbleChannel, GarbleMessage, Generator, Validator},
    ot::{ObliviousReceive, ObliviousSend, ObliviousVerify},
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
        pub(super) core: core::DEAPLeader<core::leader_state::Validate>,
    }

    impl State for Initialized {}
    impl State for Executed {}
}

use state::*;

pub struct DEAPLeader<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullInputLabels>,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + ObliviousVerify<FullInputLabels>,
{
    state: S,
    channel: GarbleChannel,
    backend: B,
    label_sender: LS,
    label_receiver: LR,
}

impl<B, LS, LR> DEAPLeader<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + ObliviousVerify<FullInputLabels> + Send,
{
    pub fn new(
        channel: GarbleChannel,
        backend: B,
        label_sender: LS,
        label_receiver: LR,
    ) -> DEAPLeader<Initialized, B, LS, LR> {
        DEAPLeader {
            state: Initialized,
            channel,
            backend,
            label_sender,
            label_receiver,
        }
    }

    /// Execute first phase of the protocol, returning the circuit output.
    ///
    /// * `circ` - Circuit to execute
    /// * `inputs` - Leader's input to the circuit
    /// * `input_labels` - Input labels used to garble leader's circuit
    /// * `delta` - Delta used to garble leader's circuit
    pub async fn execute(
        mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<(Vec<OutputValue>, DEAPLeader<Executed, B, LS, LR>), GCError> {
        let leader = core::DEAPLeader::new(circ.clone());

        // Garble circuit
        let full_gc = self
            .backend
            .generate(circ.clone(), delta, &input_labels)
            .await?;

        let (partial_gc, leader) = leader.from_full_circuit(inputs, full_gc)?;

        // Send garbled circuit to follower
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Send follower their active labels
        let leader_input_ids = inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();
        let follower_labels = input_labels
            .iter()
            .filter(|input| !leader_input_ids.contains(&input.id()))
            .cloned()
            .collect::<Vec<FullInputLabels>>();

        self.label_sender.send(follower_labels).await?;

        // Receive follower's garbled circuit
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        // Check their gc against circuit spec
        let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;

        // Retrieve active labels to follower's circuit
        let labels_ev = self.label_receiver.receive(inputs.to_vec()).await?;

        // Evaluate follower's garbled circuit
        let gc_evaluated = self.backend.evaluate(gc_ev, &labels_ev).await?;

        // Compress follower's circuit to reduce memory footprint
        let gc_cmp = self.backend.compress(gc_evaluated).await?;

        // Commit to output of follower's circuit
        let (commit, leader) = leader.from_compressed_circuit(gc_cmp)?.commit();

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
                state: Executed { core: leader },
                channel: self.channel,
                backend: self.backend,
                label_sender: self.label_sender,
                label_receiver: self.label_receiver,
            },
        ))
    }
}

impl<B, LS, LR> DEAPLeader<Executed, B, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + ObliviousVerify<FullInputLabels> + Send,
{
    /// Execute the final phase of the protocol. This proves the authenticity of the circuit output
    /// to the follower without leaking any information about leader's inputs.
    pub async fn verify(mut self) -> Result<(), GCError> {
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
        let input_labels = opening.open_labels(gc_cmp.input_labels())?;

        // Concurrently validate OT and garbling
        let gc_validate_fut = self.backend.validate_compressed(gc_cmp, opening);
        let labels_validate_fut = self.label_receiver.verify(input_labels);

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
