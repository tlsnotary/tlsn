use super::PMSLabels;
use crate::{
    msg::ServerPublicKey, KeyExchangeChannel, KeyExchangeError, KeyExchangeLead,
    KeyExchangeMessage, PublicKey,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::garble::exec::dual::DEExecute;
use p256::{ecdh::SharedSecret, AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, SecretKey};
use point_addition::PointAddition;
use share_conversion_core::fields::p256::P256;
use utils_aio::expect_msg_or_err;

pub struct KeyExchangeLeader<P, D>
where
    P: PointAddition,
    D: DEExecute,
{
    channel: KeyExchangeChannel,
    point_addition_sender: P,
    point_addition_receiver: P,
    dual_ex: D,
    leader_private_key: Option<SecretKey>,
    server_key: Option<PublicKey>,
    pms_shares: Option<[P256; 2]>,
}

impl<P, D> KeyExchangeLeader<P, D>
where
    P: PointAddition,
    D: DEExecute,
{
    /// Creates new KeyExchangeLeader.
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_sender: P,
        point_addition_receiver: P,
        dual_ex: D,
    ) -> Self {
        Self {
            channel,
            point_addition_sender,
            point_addition_receiver,
            dual_ex,
            leader_private_key: None,
            server_key: None,
            pms_shares: None,
        }
    }
}

#[async_trait]
impl<P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send, D: DEExecute + Send>
    KeyExchangeLead for KeyExchangeLeader<P, D>
{
    async fn send_client_key(
        &mut self,
        leader_private_key: SecretKey,
    ) -> Result<PublicKey, KeyExchangeError> {
        let message = expect_msg_or_err!(
            self.channel.next().await,
            KeyExchangeMessage::NotaryPublicKey,
            KeyExchangeError::Unexpected
        )?;

        let public_key = leader_private_key.public_key();
        let client_public_key = PublicKey::from_affine(
            (public_key.to_projective() + message.notary_key.to_projective()).to_affine(),
        )?;

        self.leader_private_key = Some(leader_private_key);
        Ok(client_public_key)
    }

    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        let message = KeyExchangeMessage::ServerPublicKey(ServerPublicKey { server_key });
        self.channel.send(message).await?;

        self.server_key = Some(server_key);
        Ok(())
    }

    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError> {
        let server_key = self.server_key.ok_or(KeyExchangeError::NoServerKey)?;
        let leader_private_key = self
            .leader_private_key
            .ok_or(KeyExchangeError::NoServerKey)?;

        let shared_secret = p256::ecdh::diffie_hellman(
            NonZeroScalar::from(leader_private_key),
            server_key.as_affine(),
        );
        let secret_bytes = shared_secret.raw_secret_bytes();

        let pms1 = self
            .point_addition_sender
            .compute_x_coordinate_share(shared_secret)
            .await?;
        let pms2 = self
            .point_addition_receiver
            .compute_x_coordinate_share(shared_secret)
            .await?;

        self.pms_shares = Some([pms1, pms2]);
        Ok(())
    }

    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError> {
        todo!()
    }
}
