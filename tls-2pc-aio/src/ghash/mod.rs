use mpc_aio::protocol::ot::OTError;
use tls_2pc_core::{ghash::GhashError, msgs::ghash::GhashMessage};
use utils_aio::Channel;

mod receiver;
mod sender;

type GhashChannel = Box<dyn Channel<GhashMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum GhashIOError {
    #[error("Ghash Error: {0}")]
    GhashError(#[from] GhashError),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("OT error: {0}")]
    OTError(#[from] OTError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(GhashMessage),
}

pub trait GhashMac {
    fn generate_mac(&self, message: &[u128]) -> Result<u128, GhashIOError>;
}
