use mpc_garble_core::{msg::GarbleMessage, ValueError};

use crate::{DecodeError, ExecutionError, ProveError, ValueRef, VerifyError};

/// Errors that can occur during the DEAP protocol.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum DEAPError {
    #[error("role error: {0}")]
    RoleError(String),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    GeneratorError(#[from] crate::generator::GeneratorError),
    #[error(transparent)]
    EvaluatorError(#[from] crate::evaluator::EvaluatorError),
    #[error(transparent)]
    ValueError(#[from] ValueError),
    #[error("missing encoding for value: {0:?}")]
    MissingEncoding(ValueRef),
    #[error(transparent)]
    FinalizationError(#[from] FinalizationError),
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizationError {
    #[error("DEAP instance already finalized")]
    AlreadyFinalized,
    #[error(transparent)]
    CommitmentError(#[from] mpc_core::commit::CommitmentError),
    #[error("invalid encoder seed")]
    InvalidEncoderSeed,
    #[error("invalid equality check")]
    InvalidEqualityCheck,
    #[error("invalid proof")]
    InvalidProof,
}

impl From<DEAPError> for ExecutionError {
    fn from(err: DEAPError) -> Self {
        match err {
            DEAPError::IOError(err) => ExecutionError::IOError(err),
            err => ExecutionError::ProtocolError(Box::new(err)),
        }
    }
}

impl From<DEAPError> for ProveError {
    fn from(err: DEAPError) -> Self {
        match err {
            DEAPError::IOError(err) => ProveError::IOError(err),
            err => ProveError::ProtocolError(Box::new(err)),
        }
    }
}

impl From<DEAPError> for VerifyError {
    fn from(err: DEAPError) -> Self {
        match err {
            DEAPError::IOError(err) => VerifyError::IOError(err),
            err => VerifyError::ProtocolError(Box::new(err)),
        }
    }
}

impl From<DEAPError> for DecodeError {
    fn from(err: DEAPError) -> Self {
        match err {
            DEAPError::IOError(err) => DecodeError::IOError(err),
            err => DecodeError::ProtocolError(Box::new(err)),
        }
    }
}
