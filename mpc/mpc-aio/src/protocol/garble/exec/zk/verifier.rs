use std::sync::Arc;

use crate::protocol::{
    garble::{GCError, GarbleChannel, GarbleMessage, Generator},
    ot::ObliviousSend,
};
use futures::{future::ready, SinkExt, StreamExt};
use mpc_circuits::{Circuit, Input, InputValue, OutputValue, WireGroup};
use mpc_core::garble::{exec::zk as zk_core, ActiveEncodedInput, FullEncodedInput, FullInputSet};
use utils_aio::expect_msg_or_err;

pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::LabelSetup {}
        impl Sealed for super::Verify {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Initialized;

    pub struct LabelSetup {
        pub(crate) labels: FullInputSet,
    }

    pub struct Verify {
        pub(crate) verifier: zk_core::Verifier<zk_core::verifier_state::Open>,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
    impl State for Verify {}
}

use state::*;

pub struct Verifier<S, B, LS>
where
    S: State,
    B: Generator,
    LS: ObliviousSend<FullEncodedInput>,
{
    state: S,
    circ: Arc<Circuit>,
    channel: GarbleChannel,
    backend: B,
    label_sender: Option<LS>,
}

impl<B, LS> Verifier<Initialized, B, LS>
where
    B: Generator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
{
    /// Create a new verifier.
    pub fn new(
        circ: Arc<Circuit>,
        channel: GarbleChannel,
        backend: B,
        label_sender: Option<LS>,
    ) -> Verifier<Initialized, B, LS> {
        Self {
            state: Initialized,
            circ,
            channel,
            backend,
            label_sender,
        }
    }

    /// Transfer input labels to the Prover.
    ///
    /// * `inputs` - The Verifier's inputs to the circuit for which the labels
    ///              will be sent directly.
    /// * `ot_send_inputs` - Inputs to be sent via OT.
    pub async fn setup_inputs(
        mut self,
        labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
    ) -> Result<Verifier<LabelSetup, B, LS>, GCError> {
        // Collect labels to be sent via OT
        let ot_send_labels = ot_send_inputs
            .iter()
            .map(|input| labels[input.index()].clone())
            .collect::<Vec<FullEncodedInput>>();

        // Collect active labels to be directly sent
        let direct_send_labels = inputs
            .iter()
            .map(|input| {
                labels[input.index()]
                    .select(input.value())
                    .expect("Input value should be valid")
            })
            .collect::<Vec<ActiveEncodedInput>>();

        // Concurrently execute oblivious transfers and direct label sending

        // If there are no labels to be sent via OT, we can skip the OT protocol
        let ot_send_fut = match self.label_sender {
            Some(ref mut label_sender) if ot_send_labels.len() > 0 => {
                label_sender.send(ot_send_labels)
            }
            None if ot_send_labels.len() > 0 => {
                return Err(GCError::MissingOTSender);
            }
            _ => Box::pin(ready(Ok(()))),
        };

        let direct_send_fut = self.channel.send(GarbleMessage::InputLabels(
            direct_send_labels
                .into_iter()
                .map(|labels| labels.into())
                .collect::<Vec<_>>(),
        ));

        let (ot_send_result, direct_send_result) = futures::join!(ot_send_fut, direct_send_fut);

        ot_send_result?;
        direct_send_result?;

        Ok(Verifier {
            state: LabelSetup { labels },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender: self.label_sender,
        })
    }
}

impl<B, LS> Verifier<LabelSetup, B, LS>
where
    B: Generator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
{
    /// Generate the garbled circuit and send it to the Prover, wait to receive output commitment.
    pub async fn garble(mut self) -> Result<Verifier<Verify, B, LS>, GCError> {
        let verifier = zk_core::Verifier::new(self.circ.clone());

        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.circ.clone(), self.state.labels)
            .await?;

        let (partial_gc, verifier) = verifier.from_full_circuit(full_gc)?;

        // Send garbled circuit
        self.channel
            .send(GarbleMessage::GarbledCircuit(partial_gc.into()))
            .await?;

        // Expect commitment from prover
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::HashCommitment,
            GCError::Unexpected
        )?;

        let verifier = verifier.store_commit(msg.into());

        Ok(Verifier {
            state: Verify { verifier },
            circ: self.circ,
            channel: self.channel,
            backend: self.backend,
            label_sender: self.label_sender,
        })
    }
}

impl<B, LS> Verifier<Verify, B, LS>
where
    B: Generator + Send,
    LS: ObliviousSend<FullEncodedInput> + Send,
{
    /// Execute the final phase of the protocol. This verifies the authenticity of the circuit output.
    ///
    /// **CAUTION**
    ///
    /// Calling this function reveals all of the Verifier's private inputs to the Prover! Care must be taken
    /// to ensure that this is synchronized properly with any other uses of these inputs.
    pub async fn verify(mut self) -> Result<Vec<OutputValue>, GCError> {
        // Open our circuit to the Prover
        let (opening, verifier) = self.state.verifier.open();

        self.channel
            .send(GarbleMessage::CircuitOpening(opening.into()))
            .await?;

        // Receive opening to output commitment
        let commit_opening_msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::CommitmentOpening,
            GCError::Unexpected
        )?;

        // Receive output from Prover
        let output_msg = expect_msg_or_err!(
            self.channel.next().await,
            GarbleMessage::Output,
            GCError::Unexpected
        )?;

        // Verify commitment and output to our circuit
        verifier
            .verify(commit_opening_msg.into(), output_msg.into())
            .map_err(GCError::from)
    }
}
