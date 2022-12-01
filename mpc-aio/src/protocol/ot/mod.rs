pub mod kos;
#[cfg(feature = "ot")]
pub mod mock;

use async_trait::async_trait;
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{
        CommittedOTError, ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError,
        SenderCoreError,
    },
};
use utils_aio::Channel;

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
    // #[error("muxer error")]
    // MuxerError(#[from] MuxerError),
    #[error("ot error")]
    OTError(#[from] OTError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    // #[error("unexpected message")]
    // UnexpectedMessage(OTFactoryMessage),
    #[error("{0} Sender expects {1} OTs, Receiver expects {2}")]
    SplitMismatch(String, usize, usize),
    #[error("other: {0}")]
    Other(String),
}

#[async_trait]
pub trait ObliviousSend {
    type Inputs;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive {
    type Choice;
    type Outputs;

    async fn receive(&mut self, choices: &[Self::Choice]) -> Result<Self::Outputs, OTError>;
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
pub trait ObliviousVerify {
    type Input;

    /// Verifies the correctness of the revealed OT seed
    async fn verify(self, input: Vec<Self::Input>) -> Result<(), OTError>;
}

#[async_trait]
pub trait OTSenderFactory {
    type Protocol: ObliviousSend + Send;

    /// Constructs a new Sender
    ///
    /// * `id` - Instance id
    /// * `count` - Number of OTs to provision
    async fn new_sender(
        &mut self,
        id: String,
        count: usize,
    ) -> Result<Self::Protocol, OTFactoryError>;
}

#[async_trait]
pub trait OTReceiverFactory {
    type Protocol: ObliviousReceive + Send;

    /// Constructs a new Receiver
    ///
    /// * `id` - Instance id
    /// * `count` - Number of OTs to provision
    async fn new_receiver(
        &mut self,
        id: String,
        count: usize,
    ) -> Result<Self::Protocol, OTFactoryError>;
}

#[cfg(test)]
mockall::mock! {
    pub ObliviousSender {}

    #[async_trait]
    impl ObliviousSend for ObliviousSender {
        type Inputs = Vec<[mpc_core::Block; 2]>;

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
    impl ObliviousReceive for ObliviousReceiver {
        type Choice = bool;
        type Outputs = Vec<mpc_core::Block>;

        async fn receive(
            &mut self,
            choices: &[bool],
        ) -> Result<Vec<mpc_core::Block>, OTError>;
    }
}
