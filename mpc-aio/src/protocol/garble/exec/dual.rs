//! An implementation of "Dual Execution" mode which provides authenticity but allows a malicious
//! party to learn n bits of the other party's input with 1/2^n probability of it going undetected.
//!
//! Important! Because currently we do not implement a maliciously secure equality check,
//! all private inputs of the [`DualExFollower`] may be leaked if the [`DualExLeader`] is
//! malicious. Such leakage, however, will be detected by the [`DualExFollower`] during the
//! equality check.

use crate::protocol::{
    garble::{Evaluator, Execute, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{ObliviousReceive, ObliviousSend},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{InputValue, OutputValue};
use mpc_core::garble::{
    config::GarbleConfig, exec::dual as core, gc_state, ActiveInputLabels, Error as CoreError,
    FullInputLabels, GarbledCircuit,
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

#[async_trait]
impl<B, S, R> Execute for DualExLeader<B, S, R>
where
    B: Generator + Evaluator + Send,
    S: ObliviousSend<FullInputLabels> + Send,
    R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    async fn execute(
        mut self,
        config: GarbleConfig,
        inputs: Vec<InputValue>,
    ) -> Result<Vec<OutputValue>, GCError> {
        let leader = core::DualExLeader::new(config.clone());

        let GarbleConfig {
            circ,
            generator_config,
            evaluator_config,
        } = config;

        let generator_config = generator_config.ok_or(CoreError::ConfigError(
            "Missing Generator config".to_string(),
        ))?;

        let evaluator_config = evaluator_config.ok_or(CoreError::ConfigError(
            "Missing Evaluator config".to_string(),
        ))?;

        let leader_needed_inputs = evaluator_config.filter_cached_inputs(&inputs);
        let follower_labels = generator_config.evaluator_labels(&inputs);

        let full_gc = self
            .backend
            .generate(
                circ.clone(),
                generator_config.delta,
                generator_config.input_labels,
            )
            .await?;

        let (partial_gc, leader) = leader.from_full_circuit(&inputs, full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        self.label_sender.send(follower_labels).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;

        let labels_ev = self.label_receiver.receive(leader_needed_inputs).await?;

        let evaluated_gc = self
            .backend
            .evaluate(gc_ev, [labels_ev, evaluator_config.input_labels].concat())
            .await?;
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

#[async_trait]
impl<B, S, R> Execute for DualExFollower<B, S, R>
where
    B: Generator + Evaluator + Send,
    S: ObliviousSend<FullInputLabels> + Send,
    R: ObliviousReceive<InputValue, ActiveInputLabels> + Send,
{
    async fn execute(
        mut self,
        config: GarbleConfig,
        inputs: Vec<InputValue>,
    ) -> Result<Vec<OutputValue>, GCError> {
        let follower = core::DualExFollower::new(config.clone());

        let GarbleConfig {
            circ,
            generator_config,
            evaluator_config,
        } = config;

        let generator_config = generator_config.ok_or(CoreError::ConfigError(
            "Missing Generator config".to_string(),
        ))?;

        let evaluator_config = evaluator_config.ok_or(CoreError::ConfigError(
            "Missing Evaluator config".to_string(),
        ))?;

        let follower_needed_inputs = evaluator_config.filter_cached_inputs(&inputs);
        let leader_labels = generator_config.evaluator_labels(&inputs);

        let full_gc = self
            .backend
            .generate(
                circ.clone(),
                generator_config.delta,
                generator_config.input_labels,
            )
            .await?;

        let (partial_gc, follower) = follower.from_full_circuit(&inputs, full_gc)?;

        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        self.label_sender.send(leader_labels).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::GarbledCircuit,
            GCError::Unexpected
        )?;

        let gc_ev = GarbledCircuit::<gc_state::Partial>::from_unchecked(circ, msg.into())?;

        let labels_ev = self.label_receiver.receive(follower_needed_inputs).await?;

        let evaluated_gc = self
            .backend
            .evaluate(gc_ev, [labels_ev, evaluator_config.input_labels].concat())
            .await?;

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

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use crate::protocol::{garble::backend::MockBackend, ot::mock::mock_ot_pair};
    use utils_aio::duplex::DuplexChannel;

    pub fn mock_dualex_pair() -> (impl Execute, impl Execute) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let leader = DualExLeader::new(
            Box::new(leader_channel),
            MockBackend,
            leader_sender,
            leader_receiver,
        );
        let follower = DualExFollower::new(
            Box::new(follower_channel),
            MockBackend,
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
    use std::sync::Arc;

    use super::*;
    use crate::protocol::garble::Execute;
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_core::garble::config::GarbleConfigBuilder;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_dualex() {
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());
        let (leader, follower) = mock_dualex_pair();

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_circ = circ.clone();
        let leader_task = tokio::spawn(async move {
            let config = GarbleConfigBuilder::default_dual_with_rng(
                &mut ChaCha12Rng::seed_from_u64(0),
                leader_circ,
            )
            .build()
            .unwrap();

            let leader_output = leader.execute(config, vec![leader_input]).await.unwrap();
            leader_output
        });

        let follower_circ = circ.clone();
        let follower_task = tokio::spawn(async move {
            let config = GarbleConfigBuilder::default_dual_with_rng(
                &mut ChaCha12Rng::seed_from_u64(0),
                follower_circ,
            )
            .build()
            .unwrap();

            let follower_output = follower
                .execute(config, vec![follower_input])
                .await
                .unwrap();
            follower_output
        });

        let (leader_gc_evaluated, follower_gc_evaluated) = tokio::join!(leader_task, follower_task);

        let expected_out = circ.output(0).unwrap().to_value(3u64).unwrap();

        let leader_gc_evaluated = leader_gc_evaluated.unwrap();
        let follower_gc_evaluated = follower_gc_evaluated.unwrap();

        let leader_out = leader_gc_evaluated;
        let follower_out = follower_gc_evaluated;

        assert_eq!(expected_out, leader_out[0]);
        assert_eq!(leader_out, follower_out);
    }
}
