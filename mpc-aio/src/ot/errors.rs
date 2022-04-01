use mpc_core::ot::errors::{OtReceiverCoreError, OtSenderCoreError};
use mpc_core::ot::OtMessage;
use mpc_core::proto::errors::ProtoError;
use thiserror::Error;

/// Errors that may occur when using AsyncOTSender
#[derive(Debug, Error)]
pub enum OtError {
    #[error("OT sender core error: {0}")]
    OtSenderCoreError(#[from] OtSenderCoreError),
    #[error("OT receiver core error: {0}")]
    OtReceiverCoreError(#[from] OtReceiverCoreError),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Proto error: {0}")]
    ProtoError(#[from] ProtoError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(OtMessage),
}
