/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum GhashError {
    #[error("Message was received out of order")]
    OutOfOrder,
    #[error("The other party sent data of wrong size")]
    DataLengthWrong,
    #[error("Tried to pass unsupported block count")]
    BlockCountWrong,
    #[error("Tried to finalize before the protocol was complete")]
    FinalizeCalledTooEarly,
}
