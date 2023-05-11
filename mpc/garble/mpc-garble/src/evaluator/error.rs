use mpc_core::value::{ValueId, ValueRef};
use mpc_garble_core::msg::GarbleMessage;

/// Errors that can occur while performing the role of an evaluator
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error(transparent)]
    CoreError(#[from] mpc_garble_core::EvaluatorError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    // TODO: Fix the size of this error
    #[error(transparent)]
    OTError(Box<mpc_ot::OTError>),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
    #[error("incorrect number of values: expected {expected}, got {actual}")]
    IncorrectValueCount { expected: usize, actual: usize },
    #[error(transparent)]
    TypeError(#[from] mpc_circuits::types::TypeError),
    #[error(transparent)]
    ValueError(#[from] mpc_garble_core::ValueError),
    #[error(transparent)]
    EncodingRegistryError(#[from] crate::registry::EncodingRegistryError),
    #[error("missing active encoding for value")]
    MissingEncoding(ValueRef),
    #[error("duplicate decoding for value: {0:?}")]
    DuplicateDecoding(ValueId),
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    GeneratorError(#[from] crate::generator::GeneratorError),
    #[error("invalid decoding detected")]
    InvalidDecoding,
    #[error("invalid garbled circuit detected")]
    InvalidGarbledCircuit,
}

impl From<mpc_ot::OTError> for EvaluatorError {
    fn from(err: mpc_ot::OTError) -> Self {
        Self::OTError(Box::new(err))
    }
}
