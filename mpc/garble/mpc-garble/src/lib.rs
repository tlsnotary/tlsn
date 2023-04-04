pub mod backend;
pub mod exec;
pub mod factory;

use std::sync::Arc;

use async_trait::async_trait;
use futures::channel::oneshot::Canceled;
use mpc_circuits::Circuit;
use mpc_garble_core::{
    gc_state, msgs::GarbleMessage, ActiveInputSet, CircuitOpening, FullInputSet, GarbledCircuit,
};
use utils_aio::Channel;

pub type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum GCError {
    #[error("core error")]
    CoreError(#[from] mpc_garble_core::Error),
    #[error("Label Error: {0:?}")]
    LabelError(#[from] mpc_garble_core::EncodingError),
    #[error("circuit error")]
    CircuitError(#[from] mpc_circuits::CircuitError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("ot error")]
    OTError(#[from] mpc_ot::OTError),
    #[error("OTFactoryError: {0:?}")]
    OTFactoryError(#[from] mpc_ot::OTFactoryError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GarbleMessage),
    #[error("Backend error")]
    BackendError(#[from] Canceled),
    #[error("Configured to send OTs but no OT sender was provided")]
    MissingOTSender,
    #[error("Configured to receive OTs but no OT receiver was provided")]
    MissingOTReceiver,
    #[error("Deferral Error: {0}")]
    DeferralError(String),
    #[error("Proof Error: {0}")]
    ProofError(String),
}

#[async_trait]
pub trait Generator {
    /// Asynchronously generate a garbled circuit
    async fn generate(
        &mut self,
        circ: Arc<Circuit>,
        input_labels: FullInputSet,
    ) -> Result<GarbledCircuit<gc_state::Full>, GCError>;
}

#[async_trait]
pub trait Evaluator {
    /// Asynchronously evaluate a garbled circuit
    async fn evaluate(
        &mut self,
        circ: GarbledCircuit<gc_state::Partial>,
        input_labels: ActiveInputSet,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError>;
}

#[async_trait]
pub trait Validator {
    /// Asynchronously validate an evaluated garbled circuit
    async fn validate_evaluated(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError>;

    /// Asynchronously validate a compress garbled circuit
    async fn validate_compressed(
        &mut self,
        circ: GarbledCircuit<gc_state::Compressed>,
        opening: CircuitOpening,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError>;
}

#[async_trait]
pub trait Compressor {
    /// Asynchronously compress an evaluated garbled circuit
    async fn compress(
        &mut self,
        circ: GarbledCircuit<gc_state::Evaluated>,
    ) -> Result<GarbledCircuit<gc_state::Compressed>, GCError>;
}

#[async_trait]
impl<T> ObliviousSend<FullEncodedInput> for T
where
    T: Send + ObliviousSend<[Block; 2]>,
{
    async fn send(&mut self, inputs: Vec<FullEncodedInput>) -> Result<(), OTError> {
        self.send(
            inputs
                .into_iter()
                .map(|labels| labels.iter_blocks().collect::<Vec<[Block; 2]>>())
                .flatten()
                .collect::<Vec<[Block; 2]>>(),
        )
        .await
    }
}

#[async_trait]
impl<T> ObliviousReceive<InputValue, ActiveEncodedInput> for T
where
    T: Send + ObliviousReceive<bool, Block>,
{
    async fn receive(
        &mut self,
        choices: Vec<InputValue>,
    ) -> Result<Vec<ActiveEncodedInput>, OTError> {
        let choice_bits = choices
            .iter()
            .map(|value| value.value().to_bits(value.bit_order()))
            .flatten()
            .collect::<Vec<bool>>();

        let mut blocks = self.receive(choice_bits).await?;

        Ok(choices
            .into_iter()
            .map(|value| {
                let labels = ActiveLabels::from_blocks(blocks.drain(..value.len()).collect());
                ActiveEncodedInput::from_active_labels(value.group().clone(), labels)
                    .expect("Input labels should be valid")
            })
            .collect())
    }
}

#[async_trait]
impl<T> ObliviousVerify<FullEncodedInput> for T
where
    T: Send + ObliviousVerify<[Block; 2]>,
{
    async fn verify(self, input: Vec<FullEncodedInput>) -> Result<(), OTError> {
        self.verify(
            input
                .into_iter()
                .map(|labels| labels.iter_blocks().collect::<Vec<[Block; 2]>>())
                .flatten()
                .collect(),
        )
        .await
    }
}

