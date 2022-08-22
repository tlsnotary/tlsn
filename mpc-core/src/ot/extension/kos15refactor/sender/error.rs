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
    #[error("Provided incorrect padding")]
    InvalidPadding,
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
