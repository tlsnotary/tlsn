use mpc_core::garble::{
    errors::{EvaluatorError, GeneratorError},
    GarbleMessage,
};
use thiserror::Error;

use crate::ot::OtError;

#[derive(Debug, Error)]
pub enum GarbleError {
    #[error("Encountered error during garbling: {0}")]
    GeneratorError(#[from] GeneratorError),
    #[error("Encountered error during evaluation: {0}")]
    EvaluatorError(#[from] EvaluatorError),
    #[error("Encountered OT error: {0}")]
    OtError(#[from] OtError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GarbleMessage),
    #[error("Encountered IO error: {0}")]
    IOError(#[from] std::io::Error),
}
