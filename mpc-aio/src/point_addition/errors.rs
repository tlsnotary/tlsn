use mpc_core::point_addition::PointAdditionMessage;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PointAdditionError {
    #[error("Secret share failed due to io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(PointAdditionMessage),
    #[error("There was an error in the underlying protocol")]
    UnderlyingError,
}
