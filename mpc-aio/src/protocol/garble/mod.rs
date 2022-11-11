pub mod exec;
mod label;

use std::sync::Arc;

use async_trait::async_trait;
use mpc_circuits::{Circuit, InputValue};
use mpc_core::{
    garble::{
        Delta, Evaluated, Full, GarbledCircuit, InputLabels, Partial, WireLabel, WireLabelPair,
    },
    msgs::garble::GarbleMessage,
};
use rand::thread_rng;
use utils_aio::Channel;

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
    LabelOTError(#[from] label::WireLabelError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GarbleMessage),
    #[error("garbler error")]
    GarblerError(String),
}

#[async_trait]
pub trait Generator {
    /// Asynchronously generate a garbled circuit
    async fn generate(
        &mut self,
        circ: Arc<Circuit>,
        delta: Delta,
        input_labels: Vec<InputLabels<WireLabelPair>>,
    ) -> Result<GarbledCircuit<Full>, GCError>;
}

#[async_trait]
pub trait Evaluator {
    /// Asynchronously evaluate a garbled circuit
    async fn evaluate(
        &mut self,
        circ: GarbledCircuit<Partial>,
        input_labels: Vec<InputLabels<WireLabel>>,
    ) -> Result<GarbledCircuit<Evaluated>, GCError>;
}

#[async_trait]
pub trait ExecuteWithLabels {
    /// Execute a garbled circuit with the provided labels
    async fn execute_with_labels(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
        input_labels: &[InputLabels<WireLabelPair>],
        delta: Delta,
    ) -> Result<GarbledCircuit<Evaluated>, GCError>;
}

#[async_trait]
pub trait Execute: ExecuteWithLabels {
    /// Execute a garbled circuit
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
    ) -> Result<GarbledCircuit<Evaluated>, GCError> {
        let (input_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        self.execute_with_labels(circ, inputs, &input_labels, delta)
            .await
    }
}

impl<T> Execute for T where T: ExecuteWithLabels {}

#[cfg(feature = "mock")]
mod mock {
    use super::*;
    use aes::{Aes128, NewBlockCipher};

    pub struct MockGarbler;

    #[async_trait]
    impl Generator for MockGarbler {
        async fn generate(
            &mut self,
            circ: Arc<Circuit>,
            delta: Delta,
            input_labels: Vec<InputLabels<WireLabelPair>>,
        ) -> Result<GarbledCircuit<Full>, GCError> {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            Ok(GarbledCircuit::generate(
                &cipher,
                circ,
                delta,
                &input_labels,
            )?)
        }
    }

    #[async_trait]
    impl Evaluator for MockGarbler {
        async fn evaluate(
            &mut self,
            circ: GarbledCircuit<Partial>,
            input_labels: Vec<InputLabels<WireLabel>>,
        ) -> Result<GarbledCircuit<Evaluated>, GCError> {
            let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
            Ok(circ.evaluate(&cipher, &input_labels)?)
        }
    }
}

#[cfg(feature = "mock")]
pub use mock::*;
