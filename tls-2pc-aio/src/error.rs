#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum Error {
    #[error("Encountered error with ClientConnection: {0:?}")]
    ClientConnectionError(#[from] tls_client::Error),
    #[error("Encountered error during encryption")]
    EncryptError,
    #[error("Encountered error during decryption")]
    DecryptError,
}
