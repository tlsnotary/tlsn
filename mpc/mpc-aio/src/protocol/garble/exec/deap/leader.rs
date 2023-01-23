use std::sync::Arc;

use crate::protocol::{
    garble::{Compressor, Evaluator, GCError, GarbleChannel, GarbleMessage, Generator, Validator},
    ot::{ObliviousReceive, ObliviousSend, ObliviousVerify},
};
use futures::{future::ready, SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue, WireGroup};
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
        pub(crate) input_state: InputState,
    }

    pub struct Executed {
        pub(super) core: core::DEAPLeader<core::leader_state::Validate>,
        pub(crate) input_state: InputState,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
    impl State for Executed {}

    pub(crate) struct InputState {
        pub(crate) ot_receive_inputs: Vec<Input>,
    }
}

use state::*;

pub struct DEAPLeader<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullEncodedInput>,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: Option<LS>,
    label_receiver: Option<LR>,
}

impl<B, LS, LR> DEAPLeader<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: Option<LS>,
        label_receiver: Option<LR>,
    ) -> DEAPLeader<Initialized, B, LS, LR> {
        DEAPLeader {
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
    ) -> Result<DEAPLeader<LabelSetup, B, LS, LR>, GCError> {
        let (gen_labels, ev_labels) = setup_inputs_with(
            &mut self.channel,
            self.label_sender.as_mut(),
            self.label_receiver.as_mut(),
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs.clone(),
            cached_labels,
        )
        .await?;

        Ok(DEAPLeader {
            state: LabelSetup {
                gen_labels,
                ev_labels,
                input_state: InputState {
                    ot_receive_inputs: ot_receive_inputs
                        .into_iter()
                        .map(|v| v.group().clone())
                        .collect(),
                },
            },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender: self.label_sender,
            label_receiver: self.label_receiver,
        })
    }
}

impl<B, LS, LR> DEAPLeader<LabelSetup, B, LS, LR>
where
    B: Generator + Evaluator + Compressor + Validator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Execute first phase of the protocol, returning the authenticated output.
    pub async fn execute(
        self,
    ) -> Result<(Vec<OutputValue>, DEAPLeader<Executed, B, LS, LR>), GCError> {
        // Discard summary
        let (output, _, leader) = self.execute_and_summarize().await?;
        Ok((output, leader))
    }

    /// Execute first phase of the protocol, returning the authenticated output
    /// and a summary of the follower's garbled circuit.
    ///
    /// This can be used when the labels of the evaluated circuit are needed.
    pub async fn execute_and_summarize(
        mut self,
    ) -> Result<
        (
            Vec<OutputValue>,
            GarbledCircuit<gc_state::EvaluatedSummary>,
            DEAPLeader<Executed, B, LS, LR>,
        ),
        GCError,
    > {
        let leader = core::DEAPLeader::new(self.circ.clone());

        // Garble circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

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
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        // Evaluate follower's garbled circuit
        let gc_evaluated = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        // Summarize follower's circuit to reduce memory footprint
        let gc_evaluated_summary = gc_evaluated.get_summary();

        // Also compress follower's circuit to reduce memory footprint before validating it in the next phase
        let gc_cmp = self.backend.compress(gc_evaluated).await?;

        // Commit to equality check value
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
            gc_evaluated_summary,
            DEAPLeader {
                state: Executed {
                    core: leader,
                    input_state: self.state.input_state,
                },
                circ: self.circ,
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
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
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
        let input_labels = FullInputSet::from_decoding(
            gc_cmp.input_labels().clone(),
            opening.get_delta(),
            opening.get_decoding().to_vec(),
        )?;

        // Concurrently validate OT and garbling
        let gc_validate_fut = self.backend.validate_compressed(gc_cmp, opening);

        // If we did not receive any inputs via OT, we can skip the OT validation
        let labels_validate_fut = if self.state.input_state.ot_receive_inputs.is_empty() {
            Box::pin(ready(Ok(())))
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

            label_receiver.verify(ot_received)
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
