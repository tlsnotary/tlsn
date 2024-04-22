#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The proof system returned an error when generating a proof")]
    ProvingBackendError,
    #[error("An internal error was encountered")]
    InternalError,
    #[error(transparent)]
    EncodingProviderError(#[from] crate::encodings::EncodingProviderError),
}
