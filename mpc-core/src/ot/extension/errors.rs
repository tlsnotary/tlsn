/// Errors that may occur when using OTSender
#[derive(Debug, thiserror::Error)]
pub enum ExtSenderCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT {0}")]
    BaseError(#[from] crate::ot::base::ReceiverCoreError),
    /// Base OT has not been setup
    #[error("Tried to setup extension prior to Base OT setup")]
    BaseOTNotSetup,
    /// OT Extension has not been setup
    #[error("Tried to send prior to setup")]
    NotSetup,
    #[error("Provided incorrect number of inputs")]
    InvalidInputLength,
    #[error("Tried to send after OT is already complete")]
    AlreadyComplete,
}

/// Errors that may occur when using ExtReceiverCore
#[derive(Debug, thiserror::Error)]
pub enum ExtReceiverCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT")]
    BaseError(#[from] crate::ot::base::SenderCoreError),
    /// Base OT has not been setup
    #[error("Tried to setup extension prior to Base OT setup")]
    BaseOTNotSetup,
    /// OT Extension has not been setup
    #[error("Tried to receive prior to setup")]
    NotSetup,
    /// Choice bits not derandomized
    #[error("Tried to receive prior to beaver derandomization")]
    NotDerandomized,
}
