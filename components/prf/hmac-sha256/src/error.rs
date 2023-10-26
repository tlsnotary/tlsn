use std::error::Error;

use crate::prf::state::StateError;

/// Errors that can occur during PRF computation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum PrfError {
    #[error("MPC backend error: {0:?}")]
    Mpc(Box<dyn Error + Send>),
    #[error("role error: {0:?}")]
    RoleError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<StateError> for PrfError {
    fn from(err: StateError) -> Self {
        PrfError::InvalidState(err.to_string())
    }
}

impl From<mpz_garble::MemoryError> for PrfError {
    fn from(err: mpz_garble::MemoryError) -> Self {
        PrfError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::LoadError> for PrfError {
    fn from(err: mpz_garble::LoadError) -> Self {
        PrfError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::ExecutionError> for PrfError {
    fn from(err: mpz_garble::ExecutionError) -> Self {
        PrfError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::DecodeError> for PrfError {
    fn from(err: mpz_garble::DecodeError) -> Self {
        PrfError::Mpc(Box::new(err))
    }
}
