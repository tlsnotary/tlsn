pub mod base;
pub mod extension;

pub use base::{OTReceive, Receiver, Sender};
pub use extension::{ExtOTReceive, ExtOTSend, ExtReceiver, ExtSender};
pub use mpc_core::ot::Message;

use async_trait::async_trait;
use futures::{Sink, Stream};
use mpc_core::ot::{ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError, SenderCoreError};
use std::fmt::Debug;
use thiserror::Error;

#[async_trait]
pub trait ObliviousSend {
    type Payload: Debug;

    async fn send<T: Sink<Self::Payload> + Stream>(
        &mut self,
        payload: Self::Payload,
        channel: &mut T,
    ) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive {
    type Choice: Debug;
    type Output: Debug;

    async fn receive<T: Sink<Self::Output> + Stream>(
        &mut self,
        choice: Self::Choice,
        stream: &mut T,
    ) -> Result<(), OTError>;
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
