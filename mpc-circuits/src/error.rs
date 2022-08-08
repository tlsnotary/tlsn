#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("uninitialized wire, id: {0}")]
    UninitializedWire(usize),
    /// An I/O error occurred.
    #[error("encountered error while parsing circuit: {0}")]
    ParsingError(String),
    /// An error occurred due to invalid garbler/evaluator inputs.
    #[error("invalid circuit inputs")]
    InputError,
    /// An I/O error occurred.
    #[error("encountered io error while loading circuit")]
    IoError(#[from] std::io::Error),
    /// A decoding error occurred.
    #[error("encountered prost DecodeError while loading circuit")]
    DecodeError(#[from] prost::DecodeError),
    /// Error occurred when mapping models
    #[error("encountered error while mapping protobuf model to core model")]
    MappingError,
}
