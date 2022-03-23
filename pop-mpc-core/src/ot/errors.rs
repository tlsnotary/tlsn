/// Errors that may occur when using BaseOTSender
#[derive(Debug, thiserror::Error)]
pub enum BaseOtSenderCoreError {
    /// Base OT has not been setup
    #[error("Tried to send base OT prior to setup")]
    NotSetup,
}

/// Errors that may occur when using BaseOTReceiver
#[derive(Debug, thiserror::Error)]
pub enum BaseOtReceiverCoreError {
    /// Base OT has not been setup
    #[error("Tried to receive base OT prior to setup")]
    NotSetup,
}

/// Errors that may occur when using OTSender
#[derive(Debug, thiserror::Error)]
pub enum OtSenderCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT {0}")]
    BaseOTError(#[from] BaseOtReceiverCoreError),
    /// Base OT has not been setup
    #[error("Tried to setup extension prior to Base OT setup")]
    BaseOTNotSetup,
    /// OT Extension has not been setup
    #[error("Tried to send prior to setup")]
    NotSetup,
}

/// Errors that may occur when using OTReceiver
#[derive(Debug, thiserror::Error)]
pub enum OtReceiverCoreError {
    /// Error originating from Base OT
    #[error("OT failed due to error in Base OT")]
    BaseOTError(#[from] BaseOtSenderCoreError),
    /// Base OT has not been setup
    #[error("Tried to setup extension prior to Base OT setup")]
    BaseOTNotSetup,
    /// OT Extension has not been setup
    #[error("Tried to receive prior to setup")]
    NotSetup,
}
