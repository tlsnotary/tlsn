use mpc_core::point_addition::PointAdditionError as CoreError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PointAdditionError {
    #[error("Secret share failed due to io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Encountered core error: {0:?}")]
    CoreError(#[from] CoreError),
}
