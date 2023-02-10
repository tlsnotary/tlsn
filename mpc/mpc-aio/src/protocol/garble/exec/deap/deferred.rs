//! This module contains `DeferredDEAPLeader` and `DeferredDEAPFollower`, which are used to
//! defer the execution of the equality check phase of the DEAP protocol to another context via channels.

use async_trait::async_trait;
use futures::{sink::Sink, SinkExt};

use mpc_circuits::{Input, InputValue, OutputValue};
use mpc_core::{
    garble::{exec::dual::DESummary, ActiveEncodedInput, FullEncodedInput, FullInputSet},
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::factory::AsyncFactory;

use crate::protocol::{
    garble::{exec::dual::DEExecute, Compressor, Evaluator, GCError, Generator, Validator},
    ot::{OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify},
};

use super::{follower_state, leader_state, DEAPFollower, DEAPLeader};

/// A `DeferredDEAPLeader` is a `DEAPLeader` that has deferred the execution of the equality check
/// phase to another context via a `Sink`.
pub struct DeferredDEAPLeader<S, B, LSF, LRF, LS, LR> {
    deap: DEAPLeader<leader_state::Initialized, B, LSF, LRF, LS, LR>,
    sink: S,
}

impl<S, B, LSF, LRF, LS, LR> DeferredDEAPLeader<S, B, LSF, LRF, LS, LR>
where
    S: Sink<DEAPLeader<leader_state::EqualityCheck<LR>, B, LSF, LRF, LS, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new `DeferredDEAPLeader` from a `DEAPLeader` and a `Sink`.
    pub fn new(
        leader: DEAPLeader<leader_state::Initialized, B, LSF, LRF, LS, LR>,
        sink: S,
    ) -> Self {
        Self { deap: leader, sink }
    }
}

/// A `DeferredDEAPFollower` is a `DEAPFollower` that has deferred the execution of the equality check
/// phase to another context via a `Sink`.
pub struct DeferredDEAPFollower<S, B, LSF, LRF, LS, LR> {
    deap: DEAPFollower<follower_state::Initialized, B, LSF, LRF, LS, LR>,
    sink: S,
}

impl<S, B, LSF, LRF, LS, LR> DeferredDEAPFollower<S, B, LSF, LRF, LS, LR>
where
    S: Sink<DEAPFollower<follower_state::EqualityCheck<LS>, B, LSF, LRF, LS, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    /// Create a new `DeferredDEAPFollower` from a `DEAPFollower` and a `Sink`.
    pub fn new(
        follower: DEAPFollower<follower_state::Initialized, B, LSF, LRF, LS, LR>,
        sink: S,
    ) -> Self {
        Self {
            deap: follower,
            sink,
        }
    }
}

#[async_trait]
impl<S, B, LSF, LRF, LS, LR> DEExecute for DeferredDEAPLeader<S, B, LSF, LRF, LS, LR>
where
    S: Sink<DEAPLeader<leader_state::EqualityCheck<LR>, B, LSF, LRF, LS, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Evaluator + Compressor + Validator + Clone + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + ObliviousVerify<FullEncodedInput> + Send,
{
    async fn execute(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<Vec<OutputValue>, GCError> {
        let (output, _) = self
            .execute_and_summarize(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        Ok(output)
    }

    async fn execute_and_summarize(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(Vec<OutputValue>, DESummary), GCError> {
        let (summary, leader) = self
            .deap
            .setup_inputs(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?
            .execute_until_equality_check()
            .await?;

        let (output, leader) = leader.start_equality_check().await?;

        // Send the leader down the sink for the equality check
        // to be finalized later.
        self.sink
            .send(leader)
            .await
            .map_err(|e| GCError::DeferralError(e.to_string()))?;

        Ok((output, summary))
    }

    async fn execute_skip_equality_check(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<DESummary, GCError> {
        self.deap
            .execute_skip_equality_check(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await
    }
}

#[async_trait]
impl<S, B, LSF, LRF, LS, LR> DEExecute for DeferredDEAPFollower<S, B, LSF, LRF, LS, LR>
where
    S: Sink<DEAPFollower<follower_state::EqualityCheck<LS>, B, LSF, LRF, LS, LR>> + Unpin + Send,
    S::Error: std::fmt::Display,
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    async fn execute(
        self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<Vec<OutputValue>, GCError> {
        let (outputs, _) = self
            .execute_and_summarize(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        Ok(outputs)
    }

    async fn execute_and_summarize(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<(Vec<OutputValue>, DESummary), GCError> {
        let (summary, follower) = self
            .deap
            .setup_inputs(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?
            .execute_until_equality_check()
            .await?;

        let (output, follower) = follower.start_equality_check().await?;

        // Send the follower down the sink for the equality check
        // to be finalized later.
        self.sink
            .send(follower)
            .await
            .map_err(|e| GCError::DeferralError(e.to_string()))?;

        Ok((output, summary))
    }

    async fn execute_skip_equality_check(
        mut self,
        gen_labels: FullInputSet,
        gen_inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        ot_receive_inputs: Vec<InputValue>,
        cached_labels: Vec<ActiveEncodedInput>,
    ) -> Result<DESummary, GCError> {
        self.deap
            .execute_skip_equality_check(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::{channel::mpsc::channel, StreamExt};

    use mpc_circuits::{Circuit, WireGroup, ADDER_64};
    use mpc_core::garble::exec::dual::DualExConfigBuilder;

    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::protocol::garble::exec::deap::mock::mock_deap_pair;

    #[tokio::test]
    async fn test_deferred_deap() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(ADDER_64).unwrap();

        let (leader_sender, mut leader_receiver) = channel(1);
        let (follower_sender, mut follower_receiver) = channel(1);

        let config = DualExConfigBuilder::default()
            .id("test".to_string())
            .circ(circ.clone())
            .build()
            .unwrap();

        let (leader, follower) = mock_deap_pair(config);

        let (leader, follower) = (
            DeferredDEAPLeader::new(leader, leader_sender),
            DeferredDEAPFollower::new(follower, follower_sender),
        );

        let leader_input = circ.input(0).unwrap().to_value(1u64).unwrap();
        let follower_input = circ.input(1).unwrap().to_value(2u64).unwrap();

        let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
        let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

        let leader_fut = {
            let leader_input = leader_input.clone();
            let follower_input = follower_input.clone();
            async move {
                leader
                    .execute(
                        leader_labels,
                        vec![leader_input.clone()],
                        vec![follower_input.group().clone()],
                        vec![leader_input.clone()],
                        vec![],
                    )
                    .await
                    .unwrap()
            }
        };

        let follower_fut = async move {
            follower
                .execute(
                    follower_labels,
                    vec![follower_input.clone()],
                    vec![leader_input.group().clone()],
                    vec![follower_input],
                    vec![],
                )
                .await
                .unwrap()
        };

        let (leader_out, follower_out) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_out, follower_out);

        // Pull the deferred equality check instances out of the channels
        let leader = leader_receiver.next().await.unwrap();
        let follower = follower_receiver.next().await.unwrap();

        tokio::join!(
            async move { leader.finalize_equality_check().await.unwrap() },
            async move { follower.finalize_equality_check().await.unwrap() }
        );
    }
}
