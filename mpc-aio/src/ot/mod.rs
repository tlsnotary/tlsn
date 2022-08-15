pub mod base;
pub mod extension;

pub use base::{OTReceive, OTSend, Receiver, Sender};
pub use extension::{ExtOTReceive, ExtOTSend, ExtReceiver, ExtSender};
pub use mpc_core::ot::Message;

use async_trait::async_trait;
use mpc_core::ot::{ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError, SenderCoreError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait]
pub trait ObliviousTransferSend {
    type Payload: std::fmt::Debug + 'static;

    async fn send(
        &mut self,
        payload: Self::Payload,
        stream: impl AsyncWrite + AsyncRead,
    ) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousTransferReceive {
    type Choice: std::fmt::Debug + 'static;
    type Output: std::fmt::Debug + 'static;

    async fn receive(
        &mut self,
        choice: Self::Choice,
        stream: impl AsyncWrite + AsyncRead,
    ) -> Result<Self::Output, OTError>;
}

/// Errors that may occur when using AsyncOTSender
#[derive(Debug, Error)]
pub enum OTError {
    #[error("OT sender core error: {0}")]
    SenderCoreError(#[from] SenderCoreError),
    #[error("OT receiver core error: {0}")]
    ReceiverCoreError(#[from] ReceiverCoreError),
    #[error("OT sender core error: {0}")]
    ExtSenderCoreError(#[from] ExtSenderCoreError),
    #[error("OT receiver core error: {0}")]
    ExtReceiverCoreError(#[from] ExtReceiverCoreError),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(Message),
}
