/// Errors that may occur when using OTSender
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExtSenderCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT {0}")]
    BaseError(#[from] crate::ot::base::ReceiverCoreError),
    #[error("Bad state. Expected {0}. Got {1}.")]
    BadState(String, String),
    #[error("Provided incorrect number of inputs")]
    InvalidInputLength,
    #[error("Tried to send after OT is already complete")]
    AlreadyComplete,
    #[error("Cointoss commitment check failed")]
    CommitmentCheckFailed,
    #[error("KOS15 consistency check failed")]
    ConsistencyCheckFailed,
    #[error("An internal error happened")]
    InternalError,
    #[error("Transpose Error: {0}")]
    TransposeError(#[from] matrix_transpose::TransposeError),
}

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
    #[error("Received payload of unexpected size")]
    InvalidPayloadSize,
    #[error("An internal error happened")]
    InternalError,
    #[error("Transpose Error: {0}")]
    TransposeError(#[from] matrix_transpose::TransposeError),
}
