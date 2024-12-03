#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The proof system returned an error when generating a proof: {0}")]
    ProvingBackendError(String),
    #[error(transparent)]
    EncodingProviderError(#[from] crate::encodings::EncodingProviderError),
    #[error("A mismatched count of salts for the commitment data set")]
    MismatchedSaltCommitmentDataCount,
    #[error("A mismatched count of salts for the chunk count")]
    MismatchedSaltChunkCount,
}
