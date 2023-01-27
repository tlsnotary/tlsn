//! An implementation of "Dual Execution" mode which provides authenticity but allows a malicious
//! party to learn n bits of the other party's input with 1/2^n probability of it going undetected.
//!
//! Important! Because currently we do not implement a maliciously secure equality check,
//! all private inputs of the [`DualExFollower`] may be leaked if the [`DualExLeader`] is
//! malicious. Such leakage, however, will be detected by the [`DualExFollower`] during the
//! equality check.

use std::{marker::PhantomData, sync::Arc};

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{OTFactoryError, ObliviousReceive, ObliviousSend},
};
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue, WireGroup};
use mpc_core::{
    garble::{
        exec::dual::{self as core, DualExConfig},
        gc_state, ActiveEncodedInput, ActiveInputSet, Error as CoreError, FullEncodedInput,
        FullInputSet, GarbledCircuit,
    },
    ot::config::{
        OTReceiverConfig, OTReceiverConfigBuilder, OTSenderConfig, OTSenderConfigBuilder,
    },
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

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

pub struct DualExLeader<S, B, LSF, LRF, LS, LR>
where
    S: State,
{
    config: DualExConfig,
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,

    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<B, LSF, LRF, LS, LR> DualExLeader<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DualExLeader
    pub fn new(
        config: DualExConfig,
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> DualExLeader<Initialized, B, LSF, LRF, LS, LR> {
        DualExLeader {
            config,
            state: Initialized,
            circ,
            channel,
            backend,
            label_sender_factory,
            label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
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
    ) -> Result<DualExLeader<LabelSetup, B, LSF, LRF, LS, LR>, GCError> {
        let label_sender_id = format!("{}/ot/0", self.config.id());
        let label_receiver_id = format!("{}/ot/1", self.config.id());

        let ((gen_labels, ev_labels), _) = setup_inputs_with(
            label_sender_id,
            label_receiver_id,
            &mut self.channel,
            &mut self.label_sender_factory,
            &mut self.label_receiver_factory,
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

        Ok(DualExLeader {
            config: self.config,
            state: LabelSetup {
                gen_labels,
                ev_labels,
            },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender_factory: self.label_sender_factory,
            label_receiver_factory: self.label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        })
    }
}

impl<B, LSF, LRF, LS, LR> DualExLeader<LabelSetup, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
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

    /// Execute dual execution protocol without the equality check
    ///
    /// This can be used when chaining multiple circuits together. Neither party
    /// reveals the output label decoding information.
    ///
    /// ** Warning **
    ///
    /// Do not use this method unless you know what you're doing! The output labels returned
    /// by this method can _not_ be considered correct without the equality check.
    ///
    /// Returns evaluated garbled circuit
    pub async fn execute_skip_equality_check(
        mut self,
    ) -> Result<GarbledCircuit<gc_state::EvaluatedSummary>, GCError> {
        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        // Do not reveal output decoding, send output labels commitment
        let partial_gc = full_gc.get_partial(false, true)?;

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

        if !gc_ev.has_output_commitments() {
            return Err(GCError::CoreError(CoreError::PeerError(
                "Peer did not send output labels commitment".to_string(),
            )));
        }

        // Evaluate garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        Ok(evaluated_gc.into_summary())
    }
}

pub struct DualExFollower<S, B, LSF, LRF, LS, LR>
where
    S: State,
{
    config: DualExConfig,
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender_factory: LSF,
    label_receiver_factory: LRF,

    _label_sender: PhantomData<LS>,
    _label_receiver: PhantomData<LR>,
}

impl<B, LSF, LRF, LS, LR> DualExFollower<Initialized, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
    LR: ObliviousReceive<InputValue, ActiveEncodedInput> + Send,
{
    /// Create a new DualExFollower
    pub fn new(
        config: DualExConfig,
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender_factory: LSF,
        label_receiver_factory: LRF,
    ) -> DualExFollower<Initialized, B, LSF, LRF, LS, LR> {
        DualExFollower {
            config,
            state: Initialized,
            circ,
            channel,
            backend,
            label_sender_factory,
            label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
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
    ) -> Result<DualExFollower<LabelSetup, B, LSF, LRF, LS, LR>, GCError> {
        let label_sender_id = format!("{}/ot/1", self.config.id());
        let label_receiver_id = format!("{}/ot/0", self.config.id());

        let ((gen_labels, ev_labels), _) = setup_inputs_with(
            label_sender_id,
            label_receiver_id,
            &mut self.channel,
            &mut self.label_sender_factory,
            &mut self.label_receiver_factory,
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

        Ok(DualExFollower {
            config: self.config,
            state: LabelSetup {
                gen_labels,
                ev_labels,
            },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender_factory: self.label_sender_factory,
            label_receiver_factory: self.label_receiver_factory,
            _label_sender: PhantomData,
            _label_receiver: PhantomData,
        })
    }
}

impl<B, LSF, LRF, LS, LR> DualExFollower<LabelSetup, B, LSF, LRF, LS, LR>
where
    B: Generator + Evaluator + Send,
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

    /// Execute dual execution protocol without the equality check
    ///
    /// This can be used when chaining multiple circuits together. Neither party
    /// reveals the output label decoding information.
    ///
    /// ** Warning **
    ///
    /// Do not use this method unless you know what you're doing! The output labels returned
    /// by this method can _not_ be considered correct without the equality check.
    ///
    /// Returns evaluated garbled circuit
    pub async fn execute_skip_equality_check(
        mut self,
    ) -> Result<GarbledCircuit<gc_state::EvaluatedSummary>, GCError> {
        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.gen_labels)
            .await?;

        // Do not reveal output decoding, send output labels commitment
        let partial_gc = full_gc.get_partial(false, true)?;

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

        if !gc_ev.has_output_commitments() {
            return Err(GCError::CoreError(CoreError::PeerError(
                "Peer did not send output labels commitment".to_string(),
            )));
        }

        // Evaluate garbled circuit
        let evaluated_gc = self.backend.evaluate(gc_ev, self.state.ev_labels).await?;

        Ok(evaluated_gc.into_summary())
    }
}

/// Set up input labels by exchanging directly and via oblivious transfer.
pub async fn setup_inputs_with<LSF, LRF, LS, LR>(
    label_sender_id: String,
    label_receiver_id: String,
    channel: &mut GarbleChannel,
    label_sender_factory: &mut LSF,
    label_receiver_factory: &mut LRF,
    gen_labels: FullInputSet,
    gen_inputs: Vec<InputValue>,
    ot_send_inputs: Vec<Input>,
    ot_receive_inputs: Vec<InputValue>,
    cached_labels: Vec<ActiveEncodedInput>,
) -> Result<((FullInputSet, ActiveInputSet), (Option<LS>, Option<LR>)), GCError>
where
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LRF: AsyncFactory<LR, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
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
    let ot_send_fut = async move {
        if ot_send_labels.len() > 0 {
            let count = ot_send_labels.iter().map(|labels| labels.len()).sum();

            let sender_config = OTSenderConfigBuilder::default()
                .count(count)
                .build()
                .expect("OTSenderConfig should be valid");

            let mut label_sender = label_sender_factory
                .create(label_sender_id, sender_config)
                .await?;

            let _ = label_sender.send(ot_send_labels).await?;

            Result::<_, GCError>::Ok(Some(label_sender))
        } else {
            Result::<_, GCError>::Ok(None)
        }
    };

    let direct_send_fut = channel.send(GarbleMessage::InputLabels(
        direct_send_labels
            .into_iter()
            .map(|labels| labels.into())
            .collect::<Vec<_>>(),
    ));

    // If there are no labels to be received via OT, we can skip the OT protocol
    let ot_receive_fut = async move {
        if ot_receive_inputs.len() > 0 {
            let count = ot_receive_inputs.iter().map(|input| input.len()).sum();

            let receiver_config = OTReceiverConfigBuilder::default()
                .count(count)
                .build()
                .expect("OTReceiverConfig should be valid");

            let mut label_receiver = label_receiver_factory
                .create(label_receiver_id, receiver_config)
                .await?;

            let ot_receive_labels = label_receiver.receive(ot_receive_inputs).await?;

            Result::<_, GCError>::Ok((ot_receive_labels, Some(label_receiver)))
        } else {
            Result::<_, GCError>::Ok((vec![], None))
        }
    };

    let (ot_send_result, direct_send_result, ot_receive_result) =
        futures::join!(ot_send_fut, direct_send_fut, ot_receive_fut);

    let label_sender = ot_send_result?;
    direct_send_result?;
    let (ot_receive_labels, label_receiver) = ot_receive_result?;

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

    Ok(((gen_labels, ev_labels), (label_sender, label_receiver)))
}

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use crate::protocol::{
        garble::backend::RayonBackend,
        ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender},
    };
    use mpc_core::Block;
    use utils_aio::duplex::DuplexChannel;

    pub type MockDualExLeader<S> = DualExLeader<
        S,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;
    pub type MockDualExFollower<S> = DualExFollower<
        S,
        RayonBackend,
        MockOTFactory<Block>,
        MockOTFactory<Block>,
        MockOTSender<Block>,
        MockOTReceiver<Block>,
    >;

    pub fn mock_dualex_pair(
        config: DualExConfig,
        circ: Arc<Circuit>,
    ) -> (
        MockDualExLeader<Initialized>,
        MockDualExFollower<Initialized>,
    ) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let ot_factory = MockOTFactory::new();

        let leader = DualExLeader::new(
            config.clone(),
            circ.clone(),
            Box::new(leader_channel),
            RayonBackend,
            ot_factory.clone(),
            ot_factory.clone(),
        );

        let follower = DualExFollower::new(
            config,
            circ,
            Box::new(follower_channel),
            RayonBackend,
            ot_factory.clone(),
            ot_factory.clone(),
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
    use mpc_core::garble::exec::dual::DualExConfigBuilder;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_dualex() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let config = DualExConfigBuilder::default()
            .id("test".to_string())
            .build()
            .unwrap();
        let (leader, follower) = mock_dualex_pair(config, circ.clone());

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
