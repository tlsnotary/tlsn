use super::MatrixError;

/// Errors that may occur when using ExtReceiverCore
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExtReceiverCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT")]
    BaseError(#[from] crate::ot::base::SenderCoreError),
    #[error("Bad state. Expected {0}. Got {1}.")]
    BadState(String, String),
    /// Choice bits not derandomized
    #[error("Payload contains more encrypted values than derandomized choice bits")]
    NotDerandomized,
    #[error("Tried to derandomize more OTs than setup")]
    InvalidChoiceLength,
    #[error("Received choice length which is not a multiple of 8")]
    ChoiceNotMultipleOfEight,
    #[error("Received payload of unexpected size")]
    InvalidPayloadSize,
    #[error("An internal error happened")]
    InternalError,
    #[error("Matrix Error: {0}")]
    MatrixError(#[from] MatrixError),
}
