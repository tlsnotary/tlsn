/// Errors that may occur when using BaseOTSender
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SenderCoreError {
    #[error("Bad state. Expected {0}. Got {1}.")]
    BadState(String, String),
    #[error("Provided incorrect number of inputs")]
    InvalidInputLength,
}

/// Errors that may occur when using BaseOTReceiver
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ReceiverCoreError {
    #[error("Bad state. Expected {0}. Got {1}.")]
    BadState(String, String),
    #[error("Provided incorrect number of choice bits")]
    InvalidChoiceLength,
    #[error("Sender's ciphertext is malformed")]
    MalformedCiphertext,
}
