mod follower;
mod leader;
mod msg;

use async_trait::async_trait;
pub use leader::KeyExchangeLeader;
pub use msg::KeyExchangeMessage;
use p256::PublicKey;
use utils_aio::Channel;

pub type KeyExchangeChannel = Box<dyn Channel<KeyExchangeMessage, Error = std::io::Error> + Send>;

#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("UnexpectedMessage: {0:?}")]
    UnexpectedMessage(KeyExchangeMessage),
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] point_addition::PointAdditionError),
}

#[async_trait]
pub trait KeyExchange<T> {
    async fn exchange_keys(&mut self, private_key: T) -> Result<(), KeyExchangeError>;
    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError>;
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError>;
}

pub struct PMSLabels {}
