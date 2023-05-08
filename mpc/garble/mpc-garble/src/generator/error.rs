use mpc_garble_core::ValueError;

use crate::ValueRef;

/// Errors that can occur while performing the role of a generator
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GeneratorError {
    #[error(transparent)]
    CoreError(#[from] mpc_garble_core::GeneratorError),
    // TODO: Fix the size of this error
    #[error(transparent)]
    OTError(Box<mpc_ot::OTError>),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ValueError(#[from] ValueError),
    #[error("missing encoding for value")]
    MissingEncoding(ValueRef),
    #[error(transparent)]
    EncodingRegistryError(#[from] crate::registry::EncodingRegistryError),
}

impl From<mpc_ot::OTError> for GeneratorError {
    fn from(err: mpc_ot::OTError) -> Self {
        Self::OTError(Box::new(err))
    }
}
