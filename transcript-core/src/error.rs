#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("An internal error occured")]
    InternalError,
    #[error("An internal error during serialization or deserialization")]
    SerializationError,
    #[error("Error during signature verification")]
    SignatureVerificationError,
    #[error("Attempted to create an invalid range")]
    RangeInvalid,
}
