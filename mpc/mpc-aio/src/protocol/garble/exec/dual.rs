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
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue, WireGroup};
use mpc_core::garble::{
    exec::dual as core, gc_state, ActiveInputLabels, ActiveInputLabelsSet, FullInputLabels,
    FullInputLabelsSet, GarbledCircuit,
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
        pub(crate) gen_labels: FullInputLabelsSet,
        pub(crate) ev_labels: ActiveInputLabelsSet,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
}

use state::*;

pub struct DualExLeader<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullInputLabels>,
    LR: ObliviousReceive<InputValue, ActiveInputLabels>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: LS,
    label_receiver: LR,
}

impl<B, LS, LR> DualExLeader<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: LS,
        label_receiver: LR,
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
    /// * `gen_inputs` - Inputs to be sent directly to the follower
    /// * `ot_send_inputs` - Inputs to be sent via OT
    /// * `ot_receive_inputs` - Inputs to be received via OT
    /// * `cached_labels` - Cached input labels for the follower's circuit
    pub async fn setup_inputs(
        mut self,
        gen_labels: FullInputLabelsSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveInputLabels>,
    ) -> Result<DualExLeader<LabelSetup, B, LS, LR>, GCError> {
        let (gen_labels, ev_labels) = setup_inputs(
            &mut self.channel,
            &mut self.label_sender,
            &mut self.label_receiver,
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
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub async fn execute(mut self) -> Result<Vec<OutputValue>, GCError> {
        let leader = core::DualExLeader::new(self.circ.clone());

        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        let (partial_gc, leader) = leader.from_full_circuit(full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        let leader = leader.from_evaluated_circuit(evaluated_gc)?;
        let (commit, leader) = leader.commit();

        self.channel
            .send(GarbleMessage::HashCommitment(commit.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::OutputLabelsDigest,
            GCError::Unexpected
        )?;

        let follower_check = msg.into();
        let leader = leader.check(follower_check)?;
        let (opening, gc_evaluated) = leader.reveal();

        self.channel
            .send(GarbleMessage::CommitmentOpening(opening.into()))
            .await?;

        Ok(gc_evaluated.decode()?)
    }
}

pub struct DualExFollower<S, B, LS, LR>
where
    S: State,
    B: Generator + Evaluator,
    LS: ObliviousSend<FullInputLabels>,
    LR: ObliviousReceive<InputValue, ActiveInputLabels>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: LS,
    label_receiver: LR,
}

impl<B, LS, LR> DualExFollower<Initialized, B, LS, LR>
where
    B: Generator + Evaluator + Send,
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: LS,
        label_receiver: LR,
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
    /// * `gen_inputs` - Inputs to be sent directly to the leader
    /// * `ot_send_inputs` - Inputs to be sent via OT
    /// * `ot_receive_inputs` - Inputs to be received via OT
    /// * `cached_labels` - Cached input labels for the leader's circuit
    pub async fn setup_inputs(
        mut self,
        gen_labels: FullInputLabelsSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveInputLabels>,
    ) -> Result<DualExFollower<LabelSetup, B, LS, LR>, GCError> {
        let (gen_labels, ev_labels) = setup_inputs(
            &mut self.channel,
            &mut self.label_sender,
            &mut self.label_receiver,
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
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub async fn execute(mut self) -> Result<Vec<OutputValue>, GCError> {
        let follower = core::DualExFollower::new(self.circ.clone());

        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev =
            GarbledCircuit::<gc_state::Partial>::from_unchecked(self.circ.clone(), msg.into())?;

        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        let follower = follower.from_evaluated_circuit(evaluated_gc)?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::HashCommitment,
            GCError::Unexpected
        )?;

        let leader_commit = msg.into();
        let (check, follower) = follower.reveal(leader_commit);

        self.channel
            .send(GarbleMessage::OutputLabelsDigest(check.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CommitmentOpening,
            GCError::Unexpected
        )?;
        let leader_opening = msg.into();
        let gc_evaluated = follower.verify(leader_opening)?;

        Ok(gc_evaluated.decode()?)
    }
}

async fn setup_inputs<LS, LR>(
    channel: &mut GarbleChannel,
    label_sender: &mut LS,
    label_receiver: &mut LR,
    gen_labels: FullInputLabelsSet,
    gen_inputs: Vec<InputValue>,
    ot_send_inputs: Vec<Input>,
    ot_receive_inputs: Vec<InputValue>,
    cached_labels: Vec<ActiveInputLabels>,
) -> Result<(FullInputLabelsSet, ActiveInputLabelsSet), GCError>
where
    LS: ObliviousSend<FullInputLabels> + Send,
    LR: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    let circ = gen_labels.circuit();

    let ot_send_labels = ot_send_inputs
        .iter()
        .map(|input| gen_labels[input.index()].clone())
        .collect();

    let direct_send_labels = gen_inputs
        .iter()
        .map(|input| {
            gen_labels[input.index()]
                .select(input.value())
                .expect("Input value should be valid")
        })
        .collect::<Vec<ActiveInputLabels>>();

    let ot_send_fut = label_sender.send(ot_send_labels);

    let direct_send_fut = channel.send(GarbleMessage::InputLabels(
        direct_send_labels
            .into_iter()
            .map(|labels| labels.into())
            .collect::<Vec<_>>(),
    ));

    let ot_receive_fut = label_receiver.receive(ot_receive_inputs);

    let (ot_send_result, direct_send_result, ot_receive_result) =
        futures::join!(ot_send_fut, direct_send_fut, ot_receive_fut,);

    ot_send_result?;
    direct_send_result?;
    let ot_receive_labels = ot_receive_result?;

    let msg = expect_msg_or_err!(
        channel.next().await,
        GarbleMessage::InputLabels,
        GCError::Unexpected
    )?;

    let direct_received_labels = msg
        .into_iter()
        .map(|msg| ActiveInputLabels::from_unchecked(&circ, msg.into()))
        .collect::<Result<Vec<_>, _>>()?;

    let ev_labels = ActiveInputLabelsSet::new(
        [ot_receive_labels, direct_received_labels, cached_labels].concat(),
    )?;

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
            leader_sender,
            leader_receiver,
        );

        let follower = DualExFollower::new(
            circ,
            Box::new(follower_channel),
            RayonBackend,
            follower_sender,
            follower_receiver,
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

        let leader_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

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
