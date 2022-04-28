/// Errors that may occur when using BaseOTSender
#[derive(Debug, thiserror::Error)]
pub enum SenderCoreError {
    /// Base OT has not been setup
    #[error("Tried to send base OT prior to setup")]
    NotSetup,
    #[error("Provided incorrect number of inputs")]
    InvalidInputLength,
}

/// Errors that may occur when using BaseOTReceiver
#[derive(Debug, thiserror::Error)]
pub enum ReceiverCoreError {
    /// Base OT has not been setup
    #[error("Tried to receive base OT prior to setup")]
    NotSetup,
    #[error("Provided incorrect number of choice bits")]
    InvalidChoiceLength,
}
