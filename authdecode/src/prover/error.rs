#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProverError {
    #[error("Provided empty plaintext")]
    EmptyPlaintext,
    #[error("todo")]
    Mismatch,
    #[error("Unable to put the salt of the hash into one field element")]
    NoRoomForSalt,
    #[error("Exceeded the maximum supported size of one chunk of plaintext")]
    MaxChunkSizeExceeded,
    #[error("Exceeded the maximum supported number of chunks of plaintext")]
    MaxChunkCountExceeded,
    #[error("Internal error: WrongFieldElementCount")]
    WrongFieldElementCount,
    #[error("Internal error: WrongPoseidonInput")]
    WrongPoseidonInput,
    #[error("Provided encrypted arithmetic labels of unexpected size. Expected {0}. Got {1}.")]
    IncorrectEncryptedLabelSize(usize, usize),
    #[error("Provided binary labels of unexpected size. Expected {0}. Got {1}.")]
    IncorrectBinaryLabelSize(usize, usize),
    #[error("Internal error: ErrorInPoseidonImplementation")]
    ErrorInPoseidonImplementation,
    #[error("Cannot proceed because the binary labels were not authenticated")]
    BinaryLabelAuthenticationFailed,
    #[error("Binary labels were not provided")]
    BinaryLabelsNotProvided,
    #[error("Failed to authenticate the arithmetic labels")]
    ArithmeticLabelAuthenticationFailed,
    #[error("The proof system returned an error when generating a proof")]
    ProvingBackendError,
    #[error("Internal error: WrongLastFieldElementBitCount")]
    WrongLastFieldElementBitCount,
    #[error("An internal error was encountered")]
    InternalError,
    #[error(transparent)]
    EncodingsVerifierError(#[from] crate::prover::EncodingVerifierError),
}
