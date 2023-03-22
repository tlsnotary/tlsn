pub mod backend;
pub mod exec;
pub mod factory;

use std::sync::Arc;

use async_trait::async_trait;
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
    #[error("backend error")]
    BackendError(String),
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
