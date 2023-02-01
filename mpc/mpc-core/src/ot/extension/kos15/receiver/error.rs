use crate::ot::ExtSenderCoreError;

use super::MatrixError;

/// Errors that may occur when using ExtReceiverCore
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExtReceiverCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT")]
    BaseError(#[from] crate::ot::base::SenderCoreError),
    /// Sender sent an incorrect count of encrypted OT messages
    #[error("The count of encrypted values and choice bits must match")]
    CiphertextCountWrong,
    #[error("Tried to derandomize more OTs than setup")]
    InvalidChoiceLength,
    #[error("Received payload of unexpected size")]
    InvalidPayloadSize,
    #[error("Unable to split OT after derandomization")]
    SplitAfterDerand,
    #[error("Matrix Error: {0}")]
    MatrixError(#[from] MatrixError),
}

/// Errors for committed OT verification
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CommittedOTError {
    #[error("Verification of commitment for committed OT failed")]
    CommitmentCheck,
    #[error("Committed OT sender error: {0}")]
    Sender(#[from] ExtSenderCoreError),
    #[error("Committed OT receiver error: {0}")]
    Receiver(#[from] ExtReceiverCoreError),
    #[error("Incomplete tape")]
    IncompleteTape,
    #[error("No commitment to verify")]
    NoCommitment,
    #[error("Verification failed")]
    Verify,
}
