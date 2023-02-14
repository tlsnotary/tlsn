use super::PMSLabels;
use crate::{
    msg::NotaryPublicKey, KeyExchangeChannel, KeyExchangeError, KeyExchangeFollow,
    KeyExchangeMessage, PublicKey,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::garble::exec::dual::DEExecute;
use p256::{EncodedPoint, SecretKey};
use point_addition::PointAddition;
use share_conversion_core::fields::p256::P256;
use std::borrow::Borrow;
use utils_aio::expect_msg_or_err;

pub struct KeyExchangeFollower<P, D>
where
    P: PointAddition,
    D: DEExecute,
{
    channel: KeyExchangeChannel,
    point_addition_receiver: P,
    point_addition_sender: P,
    dual_ex: D,
    follower_private_key: Option<SecretKey>,
    server_key: Option<PublicKey>,
    pms_shares: Option<[P256; 2]>,
}

impl<P, D> KeyExchangeFollower<P, D>
where
    P: PointAddition,
    D: DEExecute,
{
    /// Creates new KeyExchangeFollower
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_receiver: P,
        point_addition_sender: P,
        dual_ex: D,
    ) -> Self {
        Self {
            channel,
            point_addition_receiver,
            point_addition_sender,
            dual_ex,
            follower_private_key: None,
            server_key: None,
            pms_shares: None,
        }
    }
}

#[async_trait]
impl<P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send, D: DEExecute + Send>
    KeyExchangeFollow for KeyExchangeFollower<P, D>
{
    async fn send_public_key(
        &mut self,
        follower_private_key: SecretKey,
    ) -> Result<(), KeyExchangeError> {
        let public_key = follower_private_key.public_key();
        let message = KeyExchangeMessage::NotaryPublicKey(NotaryPublicKey {
            notary_key: public_key,
        });

        self.channel.send(message).await?;
        self.follower_private_key = Some(follower_private_key);
        Ok(())
    }

    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::ServerPublicKey,
            KeyExchangeError::Unexpected
        )?;

        self.server_key = Some(message.server_key);
        Ok(())
    }

    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError> {
        let server_key = self.server_key.ok_or(KeyExchangeError::NoServerKey)?;
        let follower_private_key = self
            .follower_private_key
            .take()
            .ok_or(KeyExchangeError::NoServerKey)?;

        // We need to mimic the ecdh::p256::diffie-hellman function without the `SharedSecret`
        // wrapper, because this makes it harder to get the result as an EC curve point.
        let shared_secret = {
            let public_projective = server_key.to_projective();
            (public_projective * follower_private_key.to_nonzero_scalar().borrow().as_ref())
                .to_affine()
        };

        let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);

        let (pms1, pms2) = futures::try_join!(
            self.point_addition_receiver
                .compute_x_coordinate_share(encoded_point),
            self.point_addition_sender
                .compute_x_coordinate_share(encoded_point),
        )?;

        self.pms_shares = Some([pms1, pms2]);
        Ok(())
    }

    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError> {
        todo!()
    }
}
