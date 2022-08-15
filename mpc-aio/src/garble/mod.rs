mod dual;
mod label;

use async_trait::async_trait;
pub use dual::{DualExFollower, DualExLeader};
use mockall::automock;
use mpc_circuits::{Circuit, InputValue};
use mpc_core::garble::{InputLabels, WireLabel, WireLabelPair};

pub trait GCExecution {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Core error: {0:?}")]
    CoreError(#[from] mpc_core::garble::Error),
    #[error("IO error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error("Received unexpected message: {0:?}")]
    UnexpectedMessage(mpc_core::msgs::garble::GarbleMessage),
    #[error("Error occurred during oblivious transfer: {0:?}")]
    OTError(#[from] crate::ot::OTError),
    #[error("Error occurred while transferring wire labels")]
    WireLabelError,
}

#[automock]
#[async_trait]
/// Trait for receiving garbled circuit wire labels from a [`WireLabelSender`] which correspond to a collection of [`InputValue`].
pub trait WireLabelReceiver: Send {
    /// Receive input labels
    async fn receive(
        &mut self,
        inputs: &[InputValue],
    ) -> Result<Vec<InputLabels<WireLabel>>, Error>;
}

#[automock]
#[async_trait]
/// Trait for sending garbled circuit wire labels to a [`WireLabelReceiver`].
pub trait WireLabelSender: Send {
    /// Send input labels
    async fn send(&mut self, inputs: &[InputLabels<WireLabelPair>]) -> Result<(), Error>;
}
