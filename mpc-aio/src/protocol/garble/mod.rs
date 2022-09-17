pub mod exec;
mod label;

use std::sync::Arc;

use async_trait::async_trait;
use mpc_circuits::{Circuit, InputValue, OutputValue};
use mpc_core::{
    garble::{Delta, InputLabels, WireLabelPair},
    msgs::garble::GarbleMessage,
};
use rand::thread_rng;
use utils_aio::Channel;

pub type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum GCError {
    #[error("core error")]
    CoreError(#[from] mpc_core::garble::Error),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("ot error")]
    LabelOTError(#[from] label::WireLabelError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GarbleMessage),
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
    ) -> Result<Vec<OutputValue>, GCError>;
}

#[async_trait]
pub trait Execute: ExecuteWithLabels {
    /// Execute a garbled circuit
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[InputValue],
    ) -> Result<Vec<OutputValue>, GCError> {
        let (input_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        self.execute_with_labels(circ, inputs, &input_labels, delta)
            .await
    }
}

impl<T> Execute for T where T: ExecuteWithLabels {}
