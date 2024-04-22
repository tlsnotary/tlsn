use crate::{backend::traits::Field, id::IdSet, msgs::MessageError};

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The prover has provided the wrong number of proofs. Expected {0}. Got {1}.")]
    WrongProofCount(usize, usize),
    #[error("The proving system returned an error when verifying a proof")]
    VerifyingBackendError,
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("An internal error was encountered")]
    InternalError,
    #[error("An custom error was encountered {0}")]
    CustomError(String),
    #[error(transparent)]
    EncodingProviderError(#[from] crate::encodings::EncodingProviderError),
    #[error("std::io::Error was encountered: {0}")]
    StdIoError(String),
}

impl<T, F> From<MessageError<T, F>> for VerifierError
where
    T: IdSet,
    F: Field,
{
    fn from(err: MessageError<T, F>) -> Self {
        VerifierError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        ))
    }
}
