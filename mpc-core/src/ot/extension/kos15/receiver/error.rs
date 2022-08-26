use super::MatrixError;

/// Errors that may occur when using ExtReceiverCore
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExtReceiverCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT")]
    BaseError(#[from] crate::ot::base::SenderCoreError),
    /// Choice bits not derandomized
    #[error("Payload contains more encrypted values than derandomized choice bits")]
    NotDerandomized,
    #[error("Tried to derandomize more OTs than setup")]
    InvalidChoiceLength,
    #[error("Received payload of unexpected size")]
    InvalidPayloadSize,
    #[error("Matrix Error: {0}")]
    MatrixError(#[from] MatrixError),
}
