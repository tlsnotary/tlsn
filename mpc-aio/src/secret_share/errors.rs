use mpc_core::secret_share::SecretShareMessage;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretShareError {
    #[error("Secret share failed due to io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(SecretShareMessage),
}
