mod follower;
mod leader;

use mpc_aio::protocol::{garble::GCError, point_addition::PointAdditionError};
use tls_2pc_core::msgs::prf::PRFMessage;
use utils_aio::Channel;

pub type PRFChannel = Box<dyn Channel<PRFMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum PRFError {
    #[error("error occurred during secret sharing")]
    SecretShareError(#[from] PointAdditionError),
    #[error("error occurred during garbled circuit protocol")]
    GCError(#[from] GCError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(PRFMessage),
}
