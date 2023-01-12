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
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, InputValue, WireGroup};
use mpc_core::garble::{
    exec::dual as core, gc_state, ActiveInputLabels, Delta, FullInputLabels, GarbledCircuit,
};
use utils_aio::expect_msg_or_err;

pub struct DualExLeader<B, S, R>
where
    B: Generator + Evaluator,
    S: ObliviousSend<FullInputLabels>,
    R: ObliviousReceive<InputValue, ActiveInputLabels>,
{
    channel: GarbleChannel,
    backend: B,
    label_sender: S,
    label_receiver: R,
}

impl<B, S, R> DualExLeader<B, S, R>
where
    B: Generator + Evaluator + Send,
    S: ObliviousSend<FullInputLabels> + Send,
    R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub fn new(channel: GarbleChannel, backend: B, label_sender: S, label_receiver: R) -> Self {
        Self {
            channel,
            backend,
            label_sender,
            label_receiver,
        }
    }
}

// #[async_trait]
// impl<B, S, R> ExecuteWithLabels for DualExLeader<B, S, R>
// where
//     B: Generator + Evaluator + Send,
//     S: ObliviousSend<FullInputLabels> + Send,
//     R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
// {
//     async fn execute_with_labels(
//         &mut self,
//         circ: Arc<Circuit>,
//         inputs: &[InputValue],
//         input_labels: &[FullInputLabels],
//         delta: Delta,
//     ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
//         let leader = core::DualExLeader::new(circ.clone());
//         let full_gc = self
//             .backend
//             .generate(circ.clone(), delta, &input_labels)
//             .await?;

//         let (partial_gc, leader) = leader.from_full_circuit(inputs, full_gc)?;

//         self.channel
//             .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
//             .await?;

//         let leader_input_ids = inputs
//             .iter()
//             .map(|input| input.index())
//             .collect::<Vec<usize>>();
//         let follower_labels = input_labels
//             .iter()
//             .filter(|input| !leader_input_ids.contains(&input.index()))
//             .cloned()
//             .collect::<Vec<FullInputLabels>>();

//         self.label_sender.send(follower_labels).await?;

//         let msg = expect_msg_or_err!(
//             self.channel.next().await,
//             GarbleMessage::GarbledCircuit,
//             GCError::Unexpected
//         )?;

//         let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;
//         let labels_ev = self.label_receiver.receive(inputs.to_vec()).await?;

//         let evaluated_gc = self.backend.evaluate(gc_ev, &labels_ev).await?;
//         let leader = leader.from_evaluated_circuit(evaluated_gc)?;
//         let (commit, leader) = leader.commit();

//         self.channel
//             .send(GarbleMessage::HashCommitment(commit.into()))
//             .await?;

//         let msg = expect_msg_or_err!(
//             self.channel.next().await,
//             GarbleMessage::OutputLabelsDigest,
//             GCError::Unexpected
//         )?;

//         let follower_check = msg.into();
//         let leader = leader.check(follower_check)?;
//         let (opening, gc_evaluated) = leader.reveal();

//         self.channel
//             .send(GarbleMessage::CommitmentOpening(opening.into()))
//             .await?;

//         Ok(gc_evaluated)
//     }
// }

pub struct DualExFollower<B, S, R>
where
    B: Generator + Evaluator,
    S: ObliviousSend<FullInputLabels>,
    R: ObliviousReceive<InputValue, ActiveInputLabels>,
{
    channel: GarbleChannel,
    backend: B,
    label_sender: S,
    label_receiver: R,
}

impl<B, S, R> DualExFollower<B, S, R>
where
    B: Generator + Evaluator + Send,
    S: ObliviousSend<FullInputLabels> + Send,
    R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    pub fn new(channel: GarbleChannel, backend: B, label_sender: S, label_receiver: R) -> Self {
        Self {
            channel,
            backend,
            label_sender,
            label_receiver,
        }
    }
}

// #[async_trait]
// impl<B, S, R> ExecuteWithLabels for DualExFollower<B, S, R>
// where
//     B: Generator + Evaluator + Send,
//     S: ObliviousSend<FullInputLabels> + Send,
//     R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
// {
//     async fn execute_with_labels(
//         &mut self,
//         circ: Arc<Circuit>,
//         inputs: &[InputValue],
//         input_labels: &[FullInputLabels],
//         delta: Delta,
//     ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
//         let follower = core::DualExFollower::new(circ.clone());
//         let full_gc = self
//             .backend
//             .generate(circ.clone(), delta, &input_labels)
//             .await?;

//         let (partial_gc, follower) = follower.from_full_circuit(inputs, full_gc)?;

//         self.channel
//             .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
//             .await?;

//         let follower_input_ids = inputs
//             .iter()
//             .map(|input| input.index())
//             .collect::<Vec<usize>>();
//         let leader_labels = input_labels
//             .iter()
//             .filter(|input| !follower_input_ids.contains(&input.index()))
//             .cloned()
//             .collect::<Vec<FullInputLabels>>();

//         self.label_sender.send(leader_labels).await?;

//         let msg = expect_msg_or_err!(
//             self.channel.next().await,
//             GarbleMessage::GarbledCircuit,
//             GCError::Unexpected
//         )?;

//         let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;
//         let labels_ev = self.label_receiver.receive(inputs.to_vec()).await?;

//         let evaluated_gc = self.backend.evaluate(gc_ev, &labels_ev).await?;
//         let follower = follower.from_evaluated_circuit(evaluated_gc)?;

//         let msg = expect_msg_or_err!(
//             self.channel.next().await,
//             GarbleMessage::HashCommitment,
//             GCError::Unexpected
//         )?;
//         let leader_commit = msg.into();
//         let (check, follower) = follower.reveal(leader_commit);

//         self.channel
//             .send(GarbleMessage::OutputLabelsDigest(check.into()))
//             .await?;

//         let msg = expect_msg_or_err!(
//             self.channel.next().await,
//             GarbleMessage::CommitmentOpening,
//             GCError::Unexpected
//         )?;
//         let leader_opening = msg.into();
//         let gc_evaluated = follower.verify(leader_opening)?;

//         Ok(gc_evaluated)
//     }
// }

// #[cfg(feature = "mock")]
// mod mock {
//     use super::*;
//     use crate::protocol::{garble::backend::MockBackend, ot::mock::mock_ot_pair};
//     use utils_aio::duplex::DuplexChannel;

//     pub fn mock_dualex_pair() -> (impl ExecuteWithLabels, impl ExecuteWithLabels) {
//         let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
//         let (leader_sender, follower_receiver) = mock_ot_pair();
//         let (follower_sender, leader_receiver) = mock_ot_pair();

//         let leader = DualExLeader::new(
//             Box::new(leader_channel),
//             MockBackend,
//             leader_sender,
//             leader_receiver,
//         );
//         let follower = DualExFollower::new(
//             Box::new(follower_channel),
//             MockBackend,
//             follower_sender,
//             follower_receiver,
//         );
//         (leader, follower)
//     }
// }

// #[cfg(feature = "mock")]
// pub use mock::mock_dualex_pair;

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::protocol::garble::Execute;
//     use mpc_circuits::ADDER_64;

//     #[tokio::test]
//     async fn test_dualex() {
//         let circ = Circuit::load_bytes(ADDER_64).unwrap();
//         let (mut leader, mut follower) = mock_dualex_pair();

//         let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
//         let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

//         let leader_circ = circ.clone();
//         let leader_task = tokio::spawn(async move {
//             let leader_output = leader.execute(leader_circ, &[leader_input]).await.unwrap();
//             leader_output
//         });

//         let follower_circ = circ.clone();
//         let follower_task = tokio::spawn(async move {
//             let follower_output = follower
//                 .execute(follower_circ, &[follower_input])
//                 .await
//                 .unwrap();
//             follower_output
//         });

//         let (leader_gc_evaluated, follower_gc_evaluated) = tokio::join!(leader_task, follower_task);

//         let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

//         let leader_gc_evaluated = leader_gc_evaluated.unwrap();
//         let follower_gc_evaluated = follower_gc_evaluated.unwrap();

//         let leader_out = leader_gc_evaluated.decode().unwrap();
//         let follower_out = follower_gc_evaluated.decode().unwrap();

//         assert_eq!(expected_out, leader_out[0]);
//         assert_eq!(leader_out, follower_out);
//     }
// }
