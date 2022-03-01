use std::fmt::{self, Display, Formatter};

#[derive(Debug, thiserror::Error)]
pub enum CircuitEvalError {
    #[error("uninitialized value, wire {0}")]
    UninitializedValue(usize),
}

/// Errors emitted by the circuit parser.
#[derive(Debug, thiserror::Error)]
pub enum CircuitParserError {
    /// An I/O error occurred.
    #[error("encountered error while parsing circuit")]
    ParsingError(#[from] anyhow::Error),
    /// An error occurred due to invalid garbler/evaluator inputs.
    #[error("invalid circuit inputs")]
    InputError,
}

/// Errors emitted by the circuit parser.
#[derive(Debug, thiserror::Error)]
pub enum CircuitLoadError {
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
