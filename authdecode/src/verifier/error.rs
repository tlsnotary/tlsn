#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifierError {
    #[error("The prover has provided the wrong number of proofs. Expected {0}. Got {1}.")]
    WrongProofCount(usize, usize),
    #[error("The Prover has provided an input that is larger than expected")]
    BigUintTooLarge,
    #[error("The proving system returned an error when verifying a proof")]
    VerifyingBackendError,
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("An internal error was encountered")]
    InternalError,
    #[error("An custom error was encountered {0}")]
    CustomError(String),
}
