mod follower;
mod leader;
mod msg;
pub mod point_addition;

use async_trait::async_trait;
use p256::PublicKey;

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
    async fn get_pms_share(&mut self) -> Result<Vec<u8>, KeyExchangeError>;
}

pub mod mock {
    use utils_aio::duplex::DuplexChannel;

    use super::*;

    pub type MockKeyExchangeLeader = KeyExchangeLeader<point_addition::mock::MockP256PointAddition>;
    pub type MockKeyExchangeFollower =
        KeyExchangeFollower<point_addition::mock::MockP256PointAddition>;

    pub fn create_mock_key_exchange_pair() -> (MockKeyExchangeLeader, MockKeyExchangeFollower) {
        let (leader_channel, follower_channel) = DuplexChannel::<KeyExchangeMessage>::new();
        let point_addition = point_addition::mock::MockP256PointAddition::new();

        let leader = KeyExchangeLeader::new(Box::new(leader_channel), point_addition.clone());
        let follower = KeyExchangeFollower::new(Box::new(follower_channel), point_addition);

        (leader, follower)
    }

    #[cfg(test)]
    mod tests {
        use p256::{
            elliptic_curve::{generic_array, AffineXCoordinate, PrimeField},
            Scalar, SecretKey,
        };
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;

        use super::*;

        #[tokio::test]
        async fn test_key_exchange() {
            let (mut leader, mut follower) = create_mock_key_exchange_pair();

            let server_secret = SecretKey::random(&mut ChaCha12Rng::seed_from_u64(0));
            let server_pk = server_secret.public_key();

            leader.set_server_key_share(server_pk).await.unwrap();

            let follower_task =
                tokio::spawn(async move { follower.get_pms_share().await.unwrap() });

            let client_key_share = leader.get_client_key_share().await.unwrap();

            let leader_pms_share = leader.get_pms_share().await.unwrap();
            let follower_pms_share = follower_task.await.unwrap();

            let leader_pms_share = generic_array::GenericArray::from_slice(&leader_pms_share);
            let follower_pms_share = generic_array::GenericArray::from_slice(&follower_pms_share);

            let leader_pms_share = Scalar::from_repr(*leader_pms_share).unwrap();
            let follower_pms_share = Scalar::from_repr(*follower_pms_share).unwrap();

            let pms = leader_pms_share + follower_pms_share;

            let expected_pms = Scalar::from_repr(
                (&client_key_share.to_projective() * &server_secret.to_nonzero_scalar())
                    .to_affine()
                    .x(),
            )
            .unwrap();

            assert_eq!(pms, expected_pms);
        }
    }
}
