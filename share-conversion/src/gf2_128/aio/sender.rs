//! This module implements the async IO sender

use super::{AddShare, Gf2_128ShareConvert, MaskedPartialValue, MulShare};
use crate::ShareConversionError;
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T: OTSenderFactory> {
    sender_factory_control: T,
    id: String,
}

impl<T: OTSenderFactory> Sender<T>
where
    T: Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue>,
{
    /// Creates a new sender
    pub fn new(sender_factory_control: T, id: String) -> Self {
        Self {
            sender_factory_control,
            id,
        }
    }

    /// Convert the shares using oblivious transfer
    pub async fn convert<U: Gf2_128ShareConvert>(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        let mut local_shares = vec![];

        if shares.is_empty() {
            return Ok(local_shares);
        }

        let mut ot_shares = MaskedPartialValue(vec![], vec![]);
        shares.iter().for_each(|share| {
            let share = U::new(*share);
            let (local, ot) = share.convert();
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        });
        let mut ot_sender = self
            .sender_factory_control
            .new_sender(self.id.clone(), ot_shares.0.len())
            .await?;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> AdditiveToMultiplicative for Sender<T>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue> + Send,
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert::<AddShare>(input).await
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> MultiplicativeToAdditive for Sender<T>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue> + Send,
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert::<MulShare>(input).await
    }
}
