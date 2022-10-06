//! An implementation of "Dual Execution" mode which provides authenticity
//! but may leak all private inputs of the [`DualExFollower`] if the [`DualExLeader`] is malicious. Either party,
//! if malicious, can learn n bits of the other's input with 1/2^n probability of it going undetected.

use std::sync::Arc;

use crate::protocol::garble::{
    label::{WireLabelOTReceive, WireLabelOTSend},
    Evaluator, ExecuteWithLabels, GCError, GarbleChannel, GarbleMessage, Generator,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, InputValue};
use mpc_core::garble::{
    exec::dual as core, Delta, Evaluated, GarbledCircuit, InputLabels, WireLabelPair,
};
use utils_aio::expect_msg_or_err;

pub struct DualExLeader<G, E, S, R>
where
    G: Generator,
    E: Evaluator,
    S: WireLabelOTSend,
    R: WireLabelOTReceive,
{
    channel: GarbleChannel,
    generator: G,
    evaluator: E,
    label_sender: S,
    label_receiver: R,
}

impl<G, E, S, R> DualExLeader<G, E, S, R>
where
    G: Generator + Send,
    E: Evaluator + Send,
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    pub fn new(
        channel: GarbleChannel,
        generator: G,
        evaluator: E,
        label_sender: S,
        label_receiver: R,
    ) -> Self {
        Self {
            channel,
            generator,
            evaluator,
            label_sender,
            label_receiver,
        }
    }
}

#[async_trait]
impl<G, E, S, R> ExecuteWithLabels for DualExLeader<G, E, S, R>
where
    G: Generator + Send,
    E: Evaluator + Send,
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<GarbledCircuit<Evaluated>, GCError> {
        let leader = core::DualExLeader::new(circ.clone());
        let full_gc = self
            .generator
            .generate(circ.clone(), delta, input_labels)
            .await?;

        let (partial_gc, leader) = leader.from_full_circuit(inputs, full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        let leader_input_ids = inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();
        let follower_labels = input_labels
            .iter()
            .filter(|input| !leader_input_ids.contains(&input.id()))
            .cloned()
            .collect::<Vec<InputLabels<WireLabelPair>>>();

        self.label_sender.send_labels(follower_labels).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev = GarbledCircuit::from_msg(circ, msg)?;
        let labels_ev = self.label_receiver.receive_labels(inputs.to_vec()).await?;

        let evaluated_gc = self.evaluator.evaluate(gc_ev, &labels_ev).await?;
        let leader = leader.from_evaluated_circuit(evaluated_gc)?;
        let (commit, leader) = leader.commit();

        self.channel
            .send(GarbleMessage::OutputCommit(commit.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::OutputCheck,
            GCError::Unexpected
        )?;

        let follower_check = msg.into();
        let leader = leader.check(follower_check)?;
        let (reveal, gc_evaluated) = leader.reveal();

        self.channel
            .send(GarbleMessage::OutputCheck(reveal.into()))
            .await?;

        Ok(gc_evaluated)
    }
}

pub struct DualExFollower<G, E, S, R>
where
    G: Generator,
    E: Evaluator,
    S: WireLabelOTSend,
    R: WireLabelOTReceive,
{
    channel: GarbleChannel,
    generator: G,
    evaluator: E,
    label_sender: S,
    label_receiver: R,
}

impl<G, E, S, R> DualExFollower<G, E, S, R>
where
    G: Generator + Send,
    E: Evaluator + Send,
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    pub fn new(
        channel: GarbleChannel,
        generator: G,
        evaluator: E,
        label_sender: S,
        label_receiver: R,
    ) -> Self {
        Self {
            channel,
            generator,
            evaluator,
            label_sender,
            label_receiver,
        }
    }
}

#[async_trait]
impl<G, E, S, R> ExecuteWithLabels for DualExFollower<G, E, S, R>
where
    G: Generator + Send,
    E: Evaluator + Send,
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<GarbledCircuit<Evaluated>, GCError> {
        let follower = core::DualExFollower::new(circ.clone());
        let full_gc = self
            .generator
            .generate(circ.clone(), delta, input_labels)
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(inputs, full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        let follower_input_ids = inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();
        let leader_labels = input_labels
            .iter()
            .filter(|input| !follower_input_ids.contains(&input.id()))
            .cloned()
            .collect::<Vec<InputLabels<WireLabelPair>>>();

        self.label_sender.send_labels(leader_labels).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;
        let gc_ev = GarbledCircuit::from_msg(circ, msg)?;
        let labels_ev = self.label_receiver.receive_labels(inputs.to_vec()).await?;

        let evaluated_gc = self.evaluator.evaluate(gc_ev, &labels_ev).await?;
        let follower = follower.from_evaluated_circuit(evaluated_gc)?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::OutputCommit,
            GCError::Unexpected
        )?;
        let leader_commit = msg.into();
        let (check, follower) = follower.reveal(leader_commit);

        self.channel
            .send(GarbleMessage::OutputCheck(check.into()))
            .await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::OutputCheck,
            GCError::Unexpected
        )?;
        let leader_check = msg.into();
        let gc_evaluated = follower.check(leader_check)?;

        Ok(gc_evaluated)
    }
}

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use crate::protocol::{
        garble::mock::{MockEvaluator, MockGenerator},
        ot::mock::mock_ot_pair,
    };
    use utils_aio::duplex::DuplexChannel;

    pub fn mock_dualex_pair() -> (impl ExecuteWithLabels, impl ExecuteWithLabels) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let leader = DualExLeader::new(
            Box::new(leader_channel),
            MockGenerator,
            MockEvaluator,
            leader_sender,
            leader_receiver,
        );
        let follower = DualExFollower::new(
            Box::new(follower_channel),
            MockGenerator,
            MockEvaluator,
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
    use crate::protocol::garble::Execute;
    use mpc_circuits::ADDER_64;

    #[tokio::test]
    async fn test_dualex() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (mut leader, mut follower) = mock_dualex_pair();

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_circ = circ.clone();
        let leader_task = tokio::spawn(async move {
            let leader_output = leader.execute(leader_circ, &[leader_input]).await.unwrap();
            leader_output
        });

        let follower_circ = circ.clone();
        let follower_task = tokio::spawn(async move {
            let follower_output = follower
                .execute(follower_circ, &[follower_input])
                .await
                .unwrap();
            follower_output
        });

        let (leader_gc_evaluated, follower_gc_evaluated) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_gc_evaluated = leader_gc_evaluated.unwrap();
        let follower_gc_evaluated = follower_gc_evaluated.unwrap();

        let leader_out = leader_gc_evaluated.decode().unwrap();
        let follower_out = follower_gc_evaluated.decode().unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
