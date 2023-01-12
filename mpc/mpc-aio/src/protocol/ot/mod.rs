pub mod kos;
#[cfg(feature = "ot")]
pub mod mock;

use async_trait::async_trait;
use mpc_core::{
    msgs::ot::{OTFactoryMessage, OTMessage},
    ot::{
        CommittedOTError, ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError,
        SenderCoreError,
    },
};
use utils_aio::{mux::MuxerError, Channel};

pub use mpc_core::ot::config;

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
mockall::mock! {
    pub ObliviousSender {}

    #[async_trait]
    impl ObliviousSend<[mpc_core::Block; 2]> for ObliviousSender {
        async fn send(
            &mut self,
            inputs: Vec<[mpc_core::Block; 2]>,
        ) -> Result<(), OTError>;
    }
}

#[cfg(test)]
mockall::mock! {
    pub ObliviousReceiver {}

    #[async_trait]
    impl ObliviousReceive<bool, mpc_core::Block> for ObliviousReceiver {
        async fn receive(
            &mut self,
            choices: Vec<bool>,
        ) -> Result<Vec<mpc_core::Block>, OTError>;
    }
}
