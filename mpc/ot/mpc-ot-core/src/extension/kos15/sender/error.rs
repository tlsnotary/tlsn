use super::MatrixError;

/// Errors that may occur when using OTSender
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExtSenderCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT {0}")]
    BaseError(#[from] crate::base::ReceiverCoreError),
    #[error("Provided incorrect number of inputs")]
    InvalidInputLength,
    #[error("Provided incorrect padding")]
    InvalidPadding,
    #[error("Cointoss commitment check failed")]
    CommitmentCheckFailed,
    #[error("KOS15 consistency check failed")]
    ConsistencyCheckFailed,
    #[error("Sender and receiver disagree on the number of OTs to generate")]
    OTNumberDisagree,
    #[error("Matrix Error: {0}")]
    MatrixError(#[from] MatrixError),
}
