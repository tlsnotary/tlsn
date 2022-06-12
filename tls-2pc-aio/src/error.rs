#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum Error {
    #[error("Encountered error during encryption")]
    EncryptError,
    #[error("Encountered error during decryption")]
    DecryptError,
}
