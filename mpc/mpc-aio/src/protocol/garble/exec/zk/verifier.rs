use crate::protocol::{
    garble::{GCError, GarbleChannel, GarbleMessage, Generator},
    ot::{OTFactoryError, ObliviousReveal, ObliviousSend},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_circuits::{Input, InputValue, OutputValue, WireGroup};
use mpc_core::{
    garble::{
        exec::zk::{self as zk_core, VerifierConfig, VerifierSummary},
        ActiveEncodedInput, FullEncodedInput, FullInputSet,
    },
    ot::config::{OTSenderConfig, OTSenderConfigBuilder},
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

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
        pub(crate) expected_output: Vec<OutputValue>,
    }

    pub struct Verify {
        pub(crate) verifier: zk_core::Verifier<zk_core::verifier_state::Open>,
        pub(crate) expected_output: Vec<OutputValue>,
    }

    impl State for Initialized {}
    impl State for LabelSetup {}
    impl State for Verify {}
}

use state::*;

pub struct Verifier<S, B, LSF, LS>
where
    S: State,
    B: Generator,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError>,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal,
{
    config: VerifierConfig,
    state: S,
    channel: GarbleChannel,
    backend: B,
    label_sender_factory: LSF,
    label_sender: Option<LS>,
}

impl<B, LSF, LS> Verifier<Initialized, B, LSF, LS>
where
    B: Generator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Create a new verifier.
    pub fn new(
        config: VerifierConfig,
        channel: GarbleChannel,
        backend: B,
        label_sender_factory: LSF,
    ) -> Verifier<Initialized, B, LSF, LS> {
        Self {
            config,
            state: Initialized,
            channel,
            backend,
            label_sender_factory,
            label_sender: None,
        }
    }

    /// Transfer input labels to the Prover.
    ///
    /// * `inputs` - The Verifier's inputs to the circuit for which the labels
    ///              will be sent directly.
    /// * `ot_send_inputs` - Inputs to be sent via OT.
    /// * `expected_output` - The expected output of the circuit.
    pub async fn setup_inputs(
        mut self,
        labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<Verifier<LabelSetup, B, LSF, LS>, GCError> {
        let label_sender_id = format!("{}/ot", self.config.id());

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
        let ot_send_fut = async {
            if ot_send_labels.len() > 0 {
                let count = ot_send_labels.iter().map(|labels| labels.len()).sum();

                let sender_config = OTSenderConfigBuilder::default()
                    .count(count)
                    .build()
                    .expect("OTSenderConfig should be valid");

                let mut label_sender = self
                    .label_sender_factory
                    .create(label_sender_id, sender_config)
                    .await?;

                let _ = label_sender.send(ot_send_labels).await?;

                Result::<_, GCError>::Ok(Some(label_sender))
            } else {
                Result::<_, GCError>::Ok(None)
            }
        };

        let direct_send_fut = self.channel.send(GarbleMessage::InputLabels(
            direct_send_labels
                .into_iter()
                .map(|labels| labels.into())
                .collect::<Vec<_>>(),
        ));

        let (ot_send_result, direct_send_result) = futures::join!(ot_send_fut, direct_send_fut);

        let label_sender = ot_send_result?;
        direct_send_result?;

        Ok(Verifier {
            config: self.config,
            state: LabelSetup {
                labels,
                expected_output,
            },
            channel: self.channel,
            backend: self.backend,
            label_sender_factory: self.label_sender_factory,
            label_sender,
        })
    }
}

impl<B, LSF, LS> Verifier<LabelSetup, B, LSF, LS>
where
    B: Generator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Generate the garbled circuit and send it to the Prover, wait to receive output commitment.
    pub async fn garble(
        mut self,
    ) -> Result<(VerifierSummary, Verifier<Verify, B, LSF, LS>), GCError> {
        let verifier = zk_core::Verifier::new(self.config.circ());

        // Generate garbled circuit
        let full_gc = self
            .backend
            .generate(self.config.circ(), self.state.labels)
            .await?;

        let generator_summary = full_gc.get_summary();

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

        let summary = VerifierSummary::new(generator_summary);

        Ok((
            summary,
            Verifier {
                config: self.config,
                state: Verify {
                    verifier,
                    expected_output: self.state.expected_output,
                },
                channel: self.channel,
                backend: self.backend,
                label_sender_factory: self.label_sender_factory,
                label_sender: self.label_sender,
            },
        ))
    }
}

impl<B, LSF, LS> Verifier<Verify, B, LSF, LS>
where
    B: Generator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    /// Execute the final phase of the protocol. This verifies the authenticity of the circuit output.
    ///
    /// **CAUTION**
    ///
    /// Calling this function reveals all of the Verifier's private inputs to the Prover! Care must be taken
    /// to ensure that this is synchronized properly with any other uses of these inputs.
    pub async fn verify(mut self) -> Result<(), GCError> {
        // Open our circuit to the Prover
        let (opening, verifier) = self.state.verifier.open();

        self.channel
            .send(GarbleMessage::CircuitOpening(opening.into()))
            .await?;

        // Open OTs to Prover
        if let Some(label_sender) = self.label_sender.take() {
            label_sender.reveal().await?;
        }

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
        let output = verifier.verify(commit_opening_msg.into(), output_msg.into())?;

        // Verify output matches expected output
        let mut expected_output = self.state.expected_output;
        expected_output.sort_by_key(|output| output.index());

        if output != expected_output {
            return Err(GCError::ProofError(
                "Output does not match expected output".to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl<B, LSF, LS> super::Verify for Verifier<Initialized, B, LSF, LS>
where
    B: Generator + Send,
    LSF: AsyncFactory<LS, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    LS: ObliviousSend<FullEncodedInput> + ObliviousReveal + Send,
{
    async fn verify(
        self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<(), GCError> {
        _ = self
            .verify_and_summarize(gen_labels, inputs, ot_send_inputs, expected_output)
            .await?;

        Ok(())
    }

    async fn verify_and_summarize(
        self,
        gen_labels: FullInputSet,
        inputs: Vec<InputValue>,
        ot_send_inputs: Vec<Input>,
        expected_output: Vec<OutputValue>,
    ) -> Result<VerifierSummary, GCError> {
        let (summary, verifier) = self
            .setup_inputs(gen_labels, inputs, ot_send_inputs, expected_output)
            .await?
            .garble()
            .await?;

        verifier.verify().await?;

        Ok(summary)
    }
}
