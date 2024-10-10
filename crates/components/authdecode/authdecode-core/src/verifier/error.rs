use crate::{backend::traits::Field, id::IdCollection, msgs::MessageError};

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The prover has provided the wrong number of proofs. Expected {0}. Got {1}.")]
    WrongProofCount(usize, usize),
    #[error("Proof verification failed with an error: {0}")]
    VerificationFailed(String),
    #[error(transparent)]
    EncodingProviderError(#[from] crate::encodings::EncodingProviderError),
}

impl<I, F> From<MessageError<I, F>> for VerifierError
where
    I: IdCollection,
    F: Field,
{
    fn from(err: MessageError<I, F>) -> Self {
        VerifierError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        ))
    }
}
