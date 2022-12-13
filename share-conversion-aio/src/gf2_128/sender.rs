//! This module implements the async IO sender

use super::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T: OTSenderFactory> {
    sender_factory: T,
    id: String,
}

impl<T: OTSenderFactory> Sender<T>
where
    T: Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope>,
{
    /// Creates a new sender
    pub fn new(sender_factory: T, id: String) -> Self {
        Self { sender_factory, id }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from<U: Gf2_128ShareConvert>(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut local_shares = vec![];

        if shares.is_empty() {
            return Ok(local_shares);
        }

        let mut ot_shares = OTEnvelope::default();
        shares.iter().for_each(|share| {
            let share = U::new(*share);
            let (local, ot) = share.convert(&mut rng);
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        });
        let mut ot_sender = self
            .sender_factory
            .new_sender(self.id.clone(), ot_shares.len())
            .await?;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> AdditiveToMultiplicative for Sender<T>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert_from::<AddShare>(input).await
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> MultiplicativeToAdditive for Sender<T>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert_from::<MulShare>(input).await
    }
}
