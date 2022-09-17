//! An implementation of "Dual Execution" mode which provides authenticity
//! but may leak all private inputs of the [`DualExFollower`] if the [`DualExLeader`] is malicious. Either party,
//! if malicious, can learn bits of the others input with 1/2^n probability of it going undetected.

use std::sync::Arc;

use crate::protocol::garble::{
    label::{WireLabelError, WireLabelOTReceive, WireLabelOTSend},
    ExecuteWithLabels, GCError, GarbleChannel, GarbleMessage,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, InputValue, OutputValue};
use mpc_core::garble::{
    exec::{dual as core, dual::state},
    Delta, GarbledCircuit, InputLabels, WireLabelPair,
};

pub struct DualExLeader<S, R>
where
    S: WireLabelOTSend,
    R: WireLabelOTReceive,
{
    channel: GarbleChannel,
    label_sender: S,
    label_receiver: R,
}

impl<S, R> DualExLeader<S, R>
where
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    pub fn new(channel: GarbleChannel, label_sender: S, label_receiver: R) -> Self {
        Self {
            channel,
            label_sender,
            label_receiver,
        }
    }
}

#[async_trait]
impl<S, R> ExecuteWithLabels for DualExLeader<S, R>
where
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<Vec<OutputValue>, GCError> {
        let leader = core::DualExLeader::new(circ.clone());

        let (gc, leader) = leader.garble(inputs, input_labels, delta)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(gc.into()))
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

        let msg = match self.channel.next().await {
            Some(GarbleMessage::GarbledCircuit(gc)) => gc,
            Some(m) => return Err(GCError::Unexpected(m)),
            None => {
                return Err(GCError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let gc_ev = GarbledCircuit::from_msg(circ, msg)?;
        let labels_ev = self.label_receiver.receive_labels(inputs.to_vec()).await?;

        let leader = leader.evaluate(&gc_ev, &labels_ev)?;
        let (commit, leader) = leader.commit();

        self.channel
            .send(GarbleMessage::OutputCommit(commit.into()))
            .await?;

        let msg = match self.channel.next().await {
            Some(GarbleMessage::OutputCheck(check)) => check,
            Some(m) => return Err(GCError::Unexpected(m)),
            None => {
                return Err(GCError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let follower_check = msg.into();
        let leader = leader.check(follower_check)?;
        let (reveal, gc_evaluated) = leader.reveal();

        self.channel
            .send(GarbleMessage::OutputCheck(reveal.into()))
            .await?;

        Ok(gc_evaluated.decode()?)
    }
}

pub struct DualExFollower<S, R>
where
    S: WireLabelOTSend,
    R: WireLabelOTReceive,
{
    channel: GarbleChannel,
    label_sender: S,
    label_receiver: R,
}

impl<S, R> DualExFollower<S, R>
where
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    pub fn new(channel: GarbleChannel, label_sender: S, label_receiver: R) -> Self {
        Self {
            channel,
            label_sender,
            label_receiver,
        }
    }
}

#[async_trait]
impl<S, R> ExecuteWithLabels for DualExFollower<S, R>
where
    S: WireLabelOTSend + Send,
    R: WireLabelOTReceive + Send,
{
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<Vec<OutputValue>, GCError> {
        let follower = core::DualExFollower::new(circ.clone());

        let (gc, follower) = follower.garble(inputs, input_labels, delta)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(gc.into()))
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

        let msg = match self.channel.next().await {
            Some(GarbleMessage::GarbledCircuit(gc)) => gc,
            Some(m) => return Err(GCError::Unexpected(m)),
            None => {
                return Err(GCError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let gc_ev = GarbledCircuit::from_msg(circ, msg)?;
        let labels_ev = self.label_receiver.receive_labels(inputs.to_vec()).await?;

        let follower = follower.evaluate(&gc_ev, &labels_ev)?;

        let msg = match self.channel.next().await {
            Some(GarbleMessage::OutputCommit(commit)) => commit,
            Some(m) => return Err(GCError::Unexpected(m)),
            None => {
                return Err(GCError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let leader_commit = msg.into();
        let (check, follower) = follower.reveal(leader_commit);

        self.channel
            .send(GarbleMessage::OutputCheck(check.into()))
            .await?;

        let msg = match self.channel.next().await {
            Some(GarbleMessage::OutputCheck(check)) => check,
            Some(m) => return Err(GCError::Unexpected(m)),
            None => {
                return Err(GCError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let leader_check = msg.into();
        let gc_evaluated = follower.check(leader_check)?;

        Ok(gc_evaluated.decode()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ot::mock::mock_ot_pair;
    use mpc_circuits::ADDER_64;
    use mpc_core::{garble::InputLabels, msgs::garble::GarbleMessage};
    use rand::thread_rng;
    use utils_aio::duplex::DuplexChannel;

    #[tokio::test]
    async fn test_dualex() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let mut leader =
            DualExLeader::new(Box::new(leader_channel), leader_sender, leader_receiver);
        let mut follower = DualExFollower::new(
            Box::new(follower_channel),
            follower_sender,
            follower_receiver,
        );

        let (leader_labels, leader_delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let (follower_labels, follower_delta) =
            InputLabels::generate(&mut thread_rng(), &circ, None);

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_circ = circ.clone();
        let leader_task = tokio::spawn(async move {
            let leader_output = leader
                .execute_with_labels(leader_circ, &[leader_input], &leader_labels, leader_delta)
                .await
                .unwrap();
            leader_output
        });

        let follower_circ = circ.clone();
        let follower_task = tokio::spawn(async move {
            let follower_output = follower
                .execute_with_labels(
                    follower_circ,
                    &[follower_input],
                    &follower_labels,
                    follower_delta,
                )
                .await
                .unwrap();
            follower_output
        });

        let (leader_out, follower_out) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();
        let leader_out = leader_out.unwrap();
        let follower_out = follower_out.unwrap();

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
