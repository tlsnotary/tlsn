use std::{marker::PhantomData, sync::Arc};

use super::{setup_inputs_with, state::*};

use crate::protocol::{
    garble::{Evaluator, GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{OTFactoryError, ObliviousReceive, ObliviousSend},
};
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue};
use mpc_core::{
    garble::{
        exec::dual::{self as core, DualExConfig},
        gc_state, ActiveEncodedInput, Error as CoreError, FullEncodedInput, FullInputSet,
        GarbledCircuit,
    },
    ot::config::{OTReceiverConfig, OTSenderConfig},
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

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
