mod follower;
mod leader;
mod msg;

use async_trait::async_trait;
use mpc_core::garble::{ActiveLabels, FullLabels};
use p256::PublicKey;

use point_addition::XCoordinateLabels;
use utils_aio::Channel;

pub use follower::KeyExchangeFollower;
pub use leader::KeyExchangeLeader;
pub use msg::KeyExchangeMessage;
pub use point_addition::{PointAddition, PointAdditionError};

pub type KeyExchangeChannel = Box<dyn Channel<KeyExchangeMessage, Error = std::io::Error> + Send>;

#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("KeyError: {0}")]
    KeyError(String),
    #[error("KeyParseError: {0}")]
    KeyParseError(String),
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("UnexpectedMessage: {0:?}")]
    UnexpectedMessage(KeyExchangeMessage),
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] point_addition::PointAdditionError),
}

#[async_trait]
pub trait KeyExchange {
    /// Returns the client's public key share.
    async fn get_client_key_share(&mut self) -> Result<PublicKey, KeyExchangeError>;
    /// Sets the server's public key share.
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), KeyExchangeError>;

    /// Computes the PMS share.
    ///
    /// Returns the PMS share as a big-endian byte array.
    async fn compute_pms_share(&mut self) -> Result<PmsShareLabels, KeyExchangeError>;
}

/// Encoded shares of the pre-master secret.
#[derive(Clone)]
pub struct PmsShareLabels {
    full_share_a_labels: FullLabels,
    full_share_b_labels: FullLabels,
    active_share_a_labels: ActiveLabels,
    active_share_b_labels: ActiveLabels,
}

impl PmsShareLabels {
    pub fn new(
        full_share_a_labels: FullLabels,
        full_share_b_labels: FullLabels,
        active_share_a_labels: ActiveLabels,
        active_share_b_labels: ActiveLabels,
    ) -> Self {
        Self {
            full_share_a_labels,
            full_share_b_labels,
            active_share_a_labels,
            active_share_b_labels,
        }
    }

    pub fn full_share_a_labels(&self) -> &FullLabels {
        &self.full_share_a_labels
    }

    pub fn full_share_b_labels(&self) -> &FullLabels {
        &self.full_share_b_labels
    }

    pub fn active_share_a_labels(&self) -> &ActiveLabels {
        &self.active_share_a_labels
    }

    pub fn active_share_b_labels(&self) -> &ActiveLabels {
        &self.active_share_b_labels
    }
}

impl From<XCoordinateLabels> for PmsShareLabels {
    fn from(x_coordinate_labels: XCoordinateLabels) -> Self {
        Self {
            full_share_a_labels: x_coordinate_labels.full_share_a_labels,
            full_share_b_labels: x_coordinate_labels.full_share_b_labels,
            active_share_a_labels: x_coordinate_labels.active_share_a_labels,
            active_share_b_labels: x_coordinate_labels.active_share_b_labels,
        }
    }
}

pub mod mock {
    use std::sync::Arc;

    use futures::lock::Mutex;
    use mpc_core::garble::ChaChaEncoder;
    use point_addition::mock::create_mock_point_addition_pair;
    use utils_aio::duplex::DuplexChannel;

    use super::*;

    pub type MockKeyExchangeLeader = KeyExchangeLeader<point_addition::mock::MockP256PointAddition>;
    pub type MockKeyExchangeFollower =
        KeyExchangeFollower<point_addition::mock::MockP256PointAddition>;

    pub fn create_mock_key_exchange_pair(
        leader_encoder: Arc<Mutex<ChaChaEncoder>>,
        follower_encoder: Arc<Mutex<ChaChaEncoder>>,
    ) -> (MockKeyExchangeLeader, MockKeyExchangeFollower) {
        let (leader_channel, follower_channel) = DuplexChannel::<KeyExchangeMessage>::new();
        let (pa_leader, pa_follower) =
            create_mock_point_addition_pair(leader_encoder, follower_encoder);

        let leader = KeyExchangeLeader::new(Box::new(leader_channel), pa_leader);
        let follower = KeyExchangeFollower::new(Box::new(follower_channel), pa_follower);

        (leader, follower)
    }

    #[cfg(test)]
    mod tests {
        use p256::SecretKey;
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;

        use super::*;

        #[tokio::test]
        async fn test_key_exchange() {
            let leader_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([0u8; 32])));
            let follower_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([1u8; 32])));

            let (mut leader, mut follower) =
                create_mock_key_exchange_pair(leader_encoder, follower_encoder);

            let server_secret = SecretKey::random(&mut ChaCha12Rng::seed_from_u64(0));
            let server_pk = server_secret.public_key();

            leader.set_server_key_share(server_pk).await.unwrap();

            let follower_task =
                tokio::spawn(async move { follower.compute_pms_share().await.unwrap() });

            let _ = leader.get_client_key_share().await.unwrap();

            leader.compute_pms_share().await.unwrap();
            follower_task.await.unwrap();
        }
    }
}
