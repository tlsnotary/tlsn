//! An implementation of "Dual Execution" mode which provides authenticity but allows a malicious
//! party to learn n bits of the other party's input with 1/2^n probability of it going undetected.
//!
//! Important! Because currently we do not implement a maliciously secure equality check,
//! all private inputs of the [`DualExFollower`] may be leaked if the [`DualExLeader`] is
//! malicious. Such leakage, however, will be detected by the [`DualExFollower`] during the
//! equality check.

use std::sync::Arc;

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{ObliviousReceive, ObliviousSend},
};
use futures::{future::ready, SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue, WireGroup};
use mpc_core::garble::{
    exec::dual as core, gc_state, ActiveEncodedInput, ActiveInputSet, FullEncodedInput,
    FullInputSet, GarbledCircuit,
};
use utils_aio::expect_msg_or_err;

mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::LabelSetup {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup {
        pub(crate) gen_labels: FullInputSet,
        pub(crate) ev_labels: ActiveInputSet,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
}

use state::*;

pub struct DualExLeader<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullEncodedInput>,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: Option<LS>,
    label_receiver: Option<LR>,
}

impl<B, LS, LR> DualExLeader<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DualExLeader
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: Option<LS>,
        label_receiver: Option<LR>,
    ) -> DualExLeader<Initialized, B, LS, LR> {
        DualExLeader {
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
    ) -> Result<DualExLeader<LabelSetup, B, LS, LR>, GCError> {
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

        Ok(DualExLeader {
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

impl<B, LS, LR> DualExLeader<LabelSetup, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Execute dual execution protocol
    ///
    /// Returns decoded output values
    pub async fn execute(self) -> Result<Vec<OutputValue>, GCError> {
        self.execute_skip_decoding()
            .await?
            .decode()
            .map_err(GCError::from)
    }

    /// Execute dual execution protocol without decoding the output values
    ///
    /// This can be used when the output labels of the evaluated circuit are needed
    /// instead of the output values
    ///
    /// Returns evaluated garbled circuit
    pub async fn execute_skip_decoding(
        mut self,
    ) -> Result<GarbledCircuit<gc_state::EvaluatedSummary>, GCError> {
        let leader = core::DualExLeader::new(self.circ.clone());

        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        let (partial_gc, leader) = leader.from_full_circuit(full_gc)?;

        // Send garbled circuit to follower
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Expect garbled circuit from follower
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        // Evaluate garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        let leader = leader.from_evaluated_circuit(evaluated_gc)?;

        // Commit to output labels
        let (commit, leader) = leader.commit();

        // Send commitment
        self.channel
            .send(GarbleMessage::HashCommitment(commit.into()))
            .await?;

        // Expect output labels digest from follower
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::OutputLabelsDigest,
            GCError::Unexpected
        )?;

        // Perform equality check
        let follower_check = msg.into();
        let leader = leader.check(follower_check)?;

        // If equality check passes, reveal output digest
        let (opening, gc_evaluated) = leader.reveal();

        self.channel
            .send(GarbleMessage::CommitmentOpening(opening.into()))
            .await?;

        Ok(gc_evaluated.into_summary())
    }
}

pub struct DualExFollower<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullEncodedInput>,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: Option<LS>,
    label_receiver: Option<LR>,
}

impl<B, LS, LR> DualExFollower<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DualExFollower
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: Option<LS>,
        label_receiver: Option<LR>,
    ) -> DualExFollower<Initialized, B, LS, LR> {
        DualExFollower {
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
    ) -> Result<DualExFollower<LabelSetup, B, LS, LR>, GCError> {
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

        Ok(DualExFollower {
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

impl<B, LS, LR> DualExFollower<LabelSetup, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Execute dual execution protocol
    ///
    /// Returns decoded output values
    pub async fn execute(self) -> Result<Vec<OutputValue>, GCError> {
        self.execute_skip_decoding()
            .await?
            .decode()
            .map_err(GCError::from)
    }

    /// Execute dual execution protocol without decoding the output values
    ///
    /// This can be used when the labels of the evaluated circuit are needed.
    ///
    /// Returns evaluated garbled circuit
    pub async fn execute_skip_decoding(
        mut self,
    ) -> Result<GarbledCircuit<gc_state::EvaluatedSummary>, GCError> {
        let follower = core::DualExFollower::new(self.circ.clone());

        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(full_gc)?;

        // Send garbled circuit to leader
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Expect garbled circuit from leader
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        // Evaluate garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        let follower = follower.from_evaluated_circuit(evaluated_gc)?;

        // Expect commitment from leader
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::HashCommitment,
            GCError::Unexpected
        )?;

        let leader_commit = msg.into();

        // Store commitment and reveal output digest
        let (check, follower) = follower.reveal(leader_commit);

        self.channel
            .send(GarbleMessage::OutputLabelsDigest(check.into()))
            .await?;

        // Expect commitment opening from leader
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CommitmentOpening,
            GCError::Unexpected
        )?;

        let leader_opening = msg.into();

        // Verify commitment opening
        let gc_evaluated = follower.verify(leader_opening)?;

        Ok(gc_evaluated.into_summary())
    }
}

/// Set up input labels by exchanging directly and via oblivious transfer.
pub async fn setup_inputs_with<LS, LR>(
    channel: &mut GarbleChannel,
    label_sender: Option<&mut LS>,
    label_receiver: Option<&mut LR>,
    gen_labels: FullInputSet,
    gen_inputs: Vec<InputValue>,
    ot_send_inputs: Vec<Input>,
    ot_receive_inputs: Vec<InputValue>,
    cached_labels: Vec<ActiveEncodedInput>,
) -> Result<(FullInputSet, ActiveInputSet), GCError>
where
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    let circ = gen_labels.circuit();

    // Collect labels to be sent via OT
    let ot_send_labels = ot_send_inputs
        .iter()
        .map(|input| gen_labels[input.index()].clone())
        .collect::<Vec<FullEncodedInput>>();

    // Collect active labels to be directly sent
    let direct_send_labels = gen_inputs
        .iter()
        .map(|input| {
            gen_labels[input.index()]
                .select(input.value())
                .expect("Input value should be valid")
        })
        .collect::<Vec<ActiveEncodedInput>>();

    // Concurrently execute oblivious transfers and direct label sending

    // If there are no labels to be sent via OT, we can skip the OT protocol
    let ot_send_fut = match label_sender {
        Some(label_sender) if ot_send_labels.len() > 0 => label_sender.send(ot_send_labels),
        None if ot_send_labels.len() > 0 => {
            return Err(GCError::MissingOTSender);
        }
        _ => Box::pin(ready(Ok(()))),
    };

    let direct_send_fut = channel.send(GarbleMessage::InputLabels(
        direct_send_labels
            .into_iter()
            .map(|labels| labels.into())
            .collect::<Vec<_>>(),
    ));

    // If there are no labels to be received via OT, we can skip the OT protocol
    let ot_receive_fut = match label_receiver {
        Some(label_receiver) if ot_receive_inputs.len() > 0 => {
            label_receiver.receive(ot_receive_inputs)
        }
        None if ot_receive_inputs.len() > 0 => {
            return Err(GCError::MissingOTReceiver);
        }
        _ => Box::pin(ready(Ok(vec![]))),
    };

    let (ot_send_result, direct_send_result, ot_receive_result) =
        futures::join!(ot_send_fut, direct_send_fut, ot_receive_fut);

    ot_send_result?;
    direct_send_result?;
    let ot_receive_labels = ot_receive_result?;

    // Expect direct labels from peer
    let msg = expect_msg_or_err!(
        channel.next().await,
        GarbleMessage::InputLabels,
        GCError::Unexpected
    )?;

    let direct_received_labels = msg
        .into_iter()
        .map(|msg| ActiveEncodedInput::from_unchecked(&circ, msg.into()))
        .collect::<Result<Vec<_>, _>>()?;

    // Collect all active labels into a set
    let ev_labels =
        ActiveInputSet::new([ot_receive_labels, direct_received_labels, cached_labels].concat())?;

    Ok((gen_labels, ev_labels))
}

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use crate::protocol::{
        garble::backend::RayonBackend,
        ot::mock::{mock_ot_pair, MockOTReceiver, MockOTSender},
    };
    use mpc_core::Block;
    use utils_aio::duplex::DuplexChannel;

    pub type MockDualExLeader<S> =
        DualExLeader<S, RayonBackend, MockOTSender<Block>, MockOTReceiver<Block>>;
    pub type MockDualExFollower<S> =
        DualExFollower<S, RayonBackend, MockOTSender<Block>, MockOTReceiver<Block>>;

    pub fn mock_dualex_pair(
        circ: Arc<Circuit>,
    ) -> (
        MockDualExLeader<Initialized>,
        MockDualExFollower<Initialized>,
    ) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let leader = DualExLeader::new(
            circ.clone(),
            Box::new(leader_channel),
            RayonBackend,
            Some(leader_sender),
            Some(leader_receiver),
        );

        let follower = DualExFollower::new(
            circ,
            Box::new(follower_channel),
            RayonBackend,
            Some(follower_sender),
            Some(follower_receiver),
        );

        (leader, follower)
    }
}

#[cfg(feature = "mock")]
pub use mock::mock_dualex_pair;

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_circuits::ADDER_64;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_dualex() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let (leader, follower) = mock_dualex_pair(circ.clone());

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

        let leader_task = {
            let leader_input = leader_input.clone();
            let follower_input = follower_input.clone();
            tokio::spawn(async move {
                leader
                    .setup_inputs(
                        leader_labels,
                        vec![leader_input.clone()],
                        vec![follower_input.group().clone()],
                        vec![leader_input.clone()],
                        vec![],
                    )
                    .await
                    .unwrap()
                    .execute()
                    .await
                    .unwrap()
            })
        };

        let follower_task = tokio::spawn(async move {
            follower
                .setup_inputs(
                    follower_labels,
                    vec![follower_input.clone()],
                    vec![leader_input.group().clone()],
                    vec![follower_input],
                    vec![],
                )
                .await
                .unwrap()
                .execute()
                .await
                .unwrap()
        });

        let (leader_out, follower_out) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_out = leader_out.unwrap();
        let follower_out = follower_out.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
