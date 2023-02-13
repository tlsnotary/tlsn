use super::PMSLabels;
use async_trait::async_trait;
use p256::{EncodedPoint, SecretKey};
use point_addition::PointAddition;
use share_conversion_core::fields::p256::P256;

use crate::{KeyExchange, KeyExchangeChannel, KeyExchangeError, KeyExchangeMessage, PublicKey};

pub struct KeyExchangeLeader<P>
where
    P: PointAddition,
{
    channel: KeyExchangeChannel,
    point_addition: P,
    private_key: SecretKey,
    server_key_share: Option<PublicKey>,
}

impl<P> KeyExchangeLeader<P>
where
    P: PointAddition,
{
    /// Creates new KeyExchangeLeader.
    pub fn new(channel: KeyExchangeChannel, point_addition: P, private_key: SecretKey) -> Self {
        Self {
            channel,
            point_addition,
            private_key,
            server_key_share: None,
        }
    }
}

#[async_trait]
impl<P: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send> KeyExchange<SecretKey>
    for KeyExchangeLeader<P>
{
    async fn exchange_keys(&mut self, private_key: SecretKey) -> Result<(), KeyExchangeError> {
        todo!()
    }
    async fn compute_pms_share(&mut self) -> Result<(), KeyExchangeError> {
        todo!()
    }
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError> {
        todo!()
    }
}
