pub mod kos;
#[cfg(feature = "mock")]
pub mod mock;

use async_trait::async_trait;
use futures::channel::oneshot::Canceled;
use mpc_ot_core::{
    msgs::{OTFactoryMessage, OTMessage},
    CommittedOTError, ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError, SenderCoreError,
};
use utils_aio::{mux::MuxerError, Channel};

pub use mpc_ot_core::config;

type OTChannel = Box<dyn Channel<OTMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum OTError {
    #[error("OT sender core error: {0}")]
    SenderCoreError(#[from] SenderCoreError),
    #[error("OT receiver core error: {0}")]
    ReceiverCoreError(#[from] ReceiverCoreError),
    #[error("OT sender core error: {0}")]
    ExtSenderCoreError(#[from] ExtSenderCoreError),
    #[error("OT receiver core error: {0}")]
    ExtReceiverCoreError(#[from] ExtReceiverCoreError),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("CommittedOT Error: {0}")]
    CommittedOT(#[from] CommittedOTError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(OTMessage),
    #[error("Received ciphertext with wrong length: expected {0}, got {1}")]
    InvalidCiphertextLength(usize, usize),
    #[error("Encountered error in backend")]
    Backend(#[from] Canceled),
}

#[derive(Debug, thiserror::Error)]
pub enum OTFactoryError {
    #[error("muxer error")]
    MuxerError(#[from] MuxerError),
    #[error("ot error")]
    OTError(#[from] OTError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("unexpected message")]
    UnexpectedMessage(OTFactoryMessage),
    #[error("{0} Sender expects {1} OTs, Receiver expects {2}")]
    SplitMismatch(String, usize, usize),
    #[error("other: {0}")]
    Other(String),
}

#[async_trait]
pub trait ObliviousSend<T> {
    async fn send(&mut self, inputs: Vec<T>) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive<T, U> {
    async fn receive(&mut self, choices: Vec<T>) -> Result<Vec<U>, OTError>;
}

#[async_trait]
pub trait ObliviousCommit {
    /// Sends a commitment to the OT seed
    async fn commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReveal {
    /// Reveals the OT seed
    async fn reveal(mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousAcceptCommit {
    /// Receives and stores a commitment to the OT seed
    async fn accept_commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousVerify<T> {
    /// Verifies the correctness of the revealed OT seed
    async fn verify(self, input: Vec<T>) -> Result<(), OTError>;
}

#[cfg(test)]
mod tests {
    use crate::mock::mock_ot_pair;
    use mpc_circuits::{InputValue, WireGroup, ADDER_64};
    use mpc_garble_core::{ActiveEncodedInput, ActiveLabels, FullEncodedInput, FullInputSet};
    use rand::thread_rng;

    #[tokio::test]
    async fn test_wire_label_transfer() {
        let circ = ADDER_64.clone();
        let full_labels = FullInputSet::generate(&mut thread_rng(), &circ, None);

        let receiver_labels = full_labels[1].clone();

        let value = circ.input(1).unwrap().to_value(4u64).unwrap();
        let expected = receiver_labels.select(value.value()).unwrap();

        let (mut sender, mut receiver) = mock_ot_pair::<Block>();
        sender.send(vec![receiver_labels]).await.unwrap();
        let received = receiver.receive(vec![value]).await.unwrap();

        assert_eq!(received[0], expected);
    }
}
