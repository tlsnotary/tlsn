/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Message was received out of order")]
    OutOfOrder,
    #[error("Received invalid message")]
    InvalidMessage,
    #[error("Method was called at the wrong time")]
    WrongState,
}
