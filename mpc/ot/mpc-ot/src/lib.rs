pub mod kos;
#[cfg(feature = "mock")]
pub mod mock;

use async_trait::async_trait;
use futures::channel::oneshot::Canceled;
use mpc_ot_core::{
    msgs::OTMessage, CommittedOTError, ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError,
    SenderCoreError,
};
use utils_aio::Channel;

pub use mpc_ot_core::config;

pub type OTChannel = Box<dyn Channel<OTMessage>>;

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
    #[error("Received ciphertext with wrong length: expected {0}, got {1}")]
    InvalidCiphertextLength(usize, usize),
    #[error("Encountered error in backend")]
    Backend(#[from] Canceled),
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("{0} Sender expects {1} OTs, Receiver expects {2}")]
    SplitMismatch(String, usize, usize),
    #[error("Other: {0}")]
    Other(String),
}

#[async_trait]
pub trait ObliviousSend<T> {
    async fn send(&self, id: &str, input: Vec<T>) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReveal {
    async fn reveal(&self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive<T, U> {
    async fn receive(&self, id: &str, choice: Vec<T>) -> Result<Vec<U>, OTError>;
}

#[async_trait]
pub trait ObliviousVerify<T> {
    async fn verify(&self, id: &str, input: Vec<T>) -> Result<(), OTError>;
}

pub trait VerifiableObliviousSend<T>: ObliviousSend<T> + ObliviousReveal {}

impl<T, U> VerifiableObliviousSend<U> for T where T: ObliviousSend<U> + ObliviousReveal {}

pub trait VerifiableObliviousReceive<T, U, V>: ObliviousReceive<T, U> + ObliviousVerify<V> {}

impl<T, U, V, X> VerifiableObliviousReceive<T, U, V> for X where
    X: ObliviousReceive<T, U> + ObliviousVerify<V>
{
}

#[async_trait]
pub trait ObliviousSendOwned<T> {
    async fn send(&mut self, inputs: Vec<T>) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceiveOwned<T, U> {
    async fn receive(&mut self, choices: Vec<T>) -> Result<Vec<U>, OTError>;
}

#[async_trait]
pub trait ObliviousCommitOwned {
    /// Sends a commitment to the OT seed
    async fn commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousRevealOwned {
    /// Reveals the OT seed
    async fn reveal(mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousAcceptCommitOwned {
    /// Receives and stores a commitment to the OT seed
    async fn accept_commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousVerifyOwned<T> {
    /// Verifies the correctness of the revealed OT seed
    async fn verify(self, input: Vec<T>) -> Result<(), OTError>;
}
