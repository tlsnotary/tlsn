/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Received invalid message, state: {0:?}, message: {1:?}")]
    InvalidMessage(Box<dyn std::fmt::Debug>, Box<dyn std::fmt::Debug>),
    #[error("Method was called at the wrong time")]
    WrongState,
}
