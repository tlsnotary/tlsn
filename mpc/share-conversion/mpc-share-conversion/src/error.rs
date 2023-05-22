use mpc_ot::OTError;

/// An error for what can go wrong during conversion
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ShareConversionError {
    #[error(transparent)]
    OTError(Box<OTError>),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Received invalid seed")]
    InvalidSeed,
    #[error("Tape not configured")]
    TapeNotConfigured,
    #[error(transparent)]
    TapeError(#[from] TapeVerificationError),
    #[error("Already finalized")]
    AlreadyFinalized,
}

impl From<mpc_ot::OTError> for ShareConversionError {
    fn from(value: mpc_ot::OTError) -> Self {
        ShareConversionError::OTError(Box::new(value))
    }
}

/// An error which can occur during tape verification
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TapeVerificationError {
    #[error("incorrect tape length: expected {0}, got {1}")]
    IncorrectLength(usize, usize),
    #[error("incorrect share type")]
    IncorrectShareType,
    #[error("incorrect share value")]
    IncorrectShareValue,
}
