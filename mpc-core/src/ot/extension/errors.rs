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
    #[error("Payload contains more encrypted values than derandomized choice bits")]
    NotDerandomized,
    #[error("Tried to derandomize more OTs than setup")]
    InvalidChoiceLength,
    #[error("Received payload of unexpected size")]
    InvalidPayloadSize,
    #[error("Tried to receive after OT is already complete")]
    AlreadyComplete,
}
