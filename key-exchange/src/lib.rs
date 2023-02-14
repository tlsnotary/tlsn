mod follower;
mod leader;
mod msg;

use async_trait::async_trait;
pub use msg::KeyExchangeMessage;
use p256::{PublicKey, SecretKey};
use utils_aio::Channel;

pub use follower::KeyExchangeFollower;
pub use leader::KeyExchangeLeader;

pub type KeyExchangeChannel = Box<dyn Channel<KeyExchangeMessage, Error = std::io::Error> + Send>;

#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("Unable to compute public key: {0}")]
    PublicKey(#[from] p256::elliptic_curve::Error),
    #[error("Server Key not set")]
    NoServerKey,
    #[error("Private key not set")]
    NoPrivateKey,
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("UnexpectedMessage: {0:?}")]
    Unexpected(KeyExchangeMessage),
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] point_addition::PointAdditionError),
}

#[async_trait]
pub trait KeyExchangeLead {
    async fn send_client_key(
        &mut self,
        leader_private_key: SecretKey,
    ) -> Result<PublicKey, KeyExchangeError>;
    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError>;
    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError>;
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError>;
}

#[async_trait]
pub trait KeyExchangeFollow {
    async fn send_public_key(
        &mut self,
        follower_private_key: SecretKey,
    ) -> Result<(), KeyExchangeError>;
    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError>;
    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError>;
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError>;
}

pub struct PMSLabels {}
