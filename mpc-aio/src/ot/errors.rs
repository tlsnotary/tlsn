use mpc_core::msgs::ot::OTMessage;
use mpc_core::ot::{ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError, SenderCoreError};
use thiserror::Error;

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
    #[error("IO error")]
    IOError,
    #[error("Received unexpected message: {0:?}")]
    Unexpected(OTMessage),
}
