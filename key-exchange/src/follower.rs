use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use p256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar, SecretKey};
use utils_aio::expect_msg_or_err;

use crate::{
    KeyExchange, KeyExchangeChannel, KeyExchangeError, KeyExchangeMessage, PointAddition, PublicKey,
};

pub struct KeyExchangeFollower<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar>,
{
    channel: KeyExchangeChannel,

    point_addition: P,

    follower_secret: SecretKey,
    follower_key_share: p256::PublicKey,
    server_key_share: Option<PublicKey>,
}

impl<P> KeyExchangeFollower<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar>,
{
    /// Creates new KeyExchangeFollower.
    pub fn new(channel: KeyExchangeChannel, point_addition: P) -> Self {
        let follower_secret = SecretKey::random(&mut rand::thread_rng());
        let follower_key_share = follower_secret.public_key();
        Self {
            channel,
            point_addition,
            follower_secret,
            follower_key_share,
            server_key_share: None,
        }
    }
}

#[async_trait]
impl<P> KeyExchange for KeyExchangeFollower<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar> + Send,
{
    async fn get_client_key_share(&mut self) -> Result<PublicKey, KeyExchangeError> {
        Err(KeyExchangeError::KeyError(
            "Follower does not have client key share".to_string(),
        ))
    }

    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), KeyExchangeError> {
        Err(KeyExchangeError::KeyError(
            "Follower receives server's key share from Leader".to_string(),
        ))
    }

    async fn get_pms_share(&mut self) -> Result<Vec<u8>, KeyExchangeError> {
        // Send public key share to the leader.
        self.channel
            .send(KeyExchangeMessage::PublicKey(
                self.follower_key_share.into(),
            ))
            .await?;

        // Receive server's ephemeral public key.
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::PublicKey,
            KeyExchangeError::UnexpectedMessage
        )?;

        let server_key: PublicKey = msg.try_into()?;

        let follower_point =
            &server_key.to_projective() * &self.follower_secret.to_nonzero_scalar();

        let pms_share = self
            .point_addition
            .share_x_coordinate(follower_point)
            .await?;

        Ok(pms_share.to_repr().to_vec())
    }
}
