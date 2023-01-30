use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use p256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar, SecretKey};
use utils_aio::expect_msg_or_err;

use crate::{
    KeyExchange, KeyExchangeChannel, KeyExchangeError, KeyExchangeMessage, PointAddition, PublicKey,
};

pub struct KeyExchangeLeader<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar>,
{
    channel: KeyExchangeChannel,

    point_addition: P,

    leader_secret: SecretKey,
    leader_key_share: p256::PublicKey,
    server_key_share: Option<PublicKey>,
}

impl<P> KeyExchangeLeader<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar>,
{
    /// Creates new KeyExchangeLeader.
    pub fn new(channel: KeyExchangeChannel, point_addition: P) -> Self {
        let leader_secret = SecretKey::random(&mut rand::thread_rng());
        let leader_key_share = leader_secret.public_key();
        Self {
            channel,
            point_addition,
            leader_secret,
            leader_key_share,
            server_key_share: None,
        }
    }
}

#[async_trait]
impl<P> KeyExchange for KeyExchangeLeader<P>
where
    P: PointAddition<Point = ProjectivePoint, XCoordinate = Scalar> + Send,
{
    async fn get_client_key_share(&mut self) -> Result<PublicKey, KeyExchangeError> {
        let msg = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::PublicKey,
            KeyExchangeError::UnexpectedMessage
        )?;

        let follower_key: PublicKey = msg.try_into()?;

        let shared_key = self.leader_key_share.to_projective() + follower_key.to_projective();
        let client_key_share = PublicKey::from_affine(shared_key.to_affine())
            .map_err(|e| KeyExchangeError::KeyError(e.to_string()))?;

        Ok(client_key_share)
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), KeyExchangeError> {
        self.server_key_share = Some(key.clone());

        self.channel
            .send(KeyExchangeMessage::PublicKey(key.into()))
            .await?;

        Ok(())
    }

    async fn get_pms_share(&mut self) -> Result<Vec<u8>, KeyExchangeError> {
        let server_key = self
            .server_key_share
            .clone()
            .ok_or(KeyExchangeError::KeyError(
                "Server key share not set".to_string(),
            ))?;

        let leader_point = &server_key.to_projective() * &self.leader_secret.to_nonzero_scalar();

        let pms_share = self.point_addition.share_x_coordinate(leader_point).await?;

        Ok(pms_share.to_repr().to_vec())
    }
}
