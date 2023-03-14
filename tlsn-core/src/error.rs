#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("An internal error during serialization or deserialization")]
    SerializationError,
    #[error("Attempted to create an invalid range")]
    RangeInvalid,
}
