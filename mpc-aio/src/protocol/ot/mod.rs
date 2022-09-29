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
    async fn commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReveal {
    async fn reveal(mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousAcceptCommit {
    async fn accept_commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousVerify {
    type Output;

    async fn verify(self) -> Result<Vec<Self::Output>, OTError>;
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
