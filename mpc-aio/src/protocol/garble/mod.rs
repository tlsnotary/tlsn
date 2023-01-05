pub mod backend;
pub mod exec;
mod label;

use std::sync::Arc;

use async_trait::async_trait;
use mpc_circuits::{Circuit, InputValue};
use mpc_core::{
    garble::{gc_state, ActiveInputLabels, CircuitOpening, Delta, FullInputLabels, GarbledCircuit},
    msgs::garble::GarbleMessage,
};
use rand::thread_rng;
use utils_aio::Channel;

use super::ot::OTError;

pub type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum GCError {
    #[error("core error")]
    CoreError(#[from] mpc_core::garble::Error),
    #[error("circuit error")]
    CircuitError(#[from] mpc_circuits::CircuitError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("ot error")]
    OTError(#[from] OTError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GarbleMessage),
    #[error("backend error")]
    BackendError(String),
}

#[async_trait]
pub trait Generator {
    /// Asynchronously generate a garbled circuit
    async fn generate(
        &mut self,
        circ: Arc<Circuit>,
        delta: Delta,
        input_labels: &[FullInputLabels],
    ) -> Result<GarbledCircuit<gc_state::Full>, GCError>;
}

#[async_trait]
pub trait Evaluator {
    /// Asynchronously evaluate a garbled circuit
    async fn evaluate(
        &mut self,
        circ: GarbledCircuit<gc_state::Partial>,
        input_labels: &[ActiveInputLabels],
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
pub trait ExecuteWithLabels {
    /// Execute a garbled circuit with the provided labels
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[FullInputLabels],
        delta: Delta,
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError>;
}

#[async_trait]
pub trait Execute: ExecuteWithLabels {
    /// Execute a garbled circuit
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
    ) -> Result<GarbledCircuit<gc_state::Evaluated>, GCError> {
        let (input_labels, delta) = FullInputLabels::generate_set(&mut thread_rng(), &circ, None);
        self.execute_with_labels(circ, inputs, &input_labels, delta)
            .await
    }
}

impl<T> Execute for T where T: ExecuteWithLabels {}
