//! This module implements the async IO sender

use super::{AddShare, Gf2_128HomomorphicConvert, MaskedPartialValue, MulShare};
use crate::HomomorphicError;
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T: OTSenderFactory, U: Gf2_128HomomorphicConvert> {
    sender_factory_control: T,
    share_type: std::marker::PhantomData<U>,
}

impl<T: OTSenderFactory, U: Gf2_128HomomorphicConvert> Sender<T, U>
where
    T: Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue>,
{
    /// Creates a new sender
    pub fn new(sender_factory_control: T) -> Self {
        Self {
            sender_factory_control,
            share_type: std::marker::PhantomData,
        }
    }

    /// Convert the shares using oblivious transfer
    pub async fn convert(
        &mut self,
        shares: &[u128],
        id: String,
    ) -> Result<Vec<u128>, HomomorphicError> {
        let mut local_shares = vec![];
        let mut ot_shares = MaskedPartialValue(vec![], vec![]);
        shares.iter().for_each(|share| {
            let share = U::new(*share);
            let (local, ot) = share.convert();
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        });
        let mut ot_sender = self
            .sender_factory_control
            .new_sender(id, ot_shares.0.len())
            .await?;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> AdditiveToMultiplicative for Sender<T, AddShare>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue> + Send,
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
        id: String,
    ) -> Result<Vec<Self::FieldElement>, HomomorphicError> {
        self.convert(input, id).await
    }
}

#[async_trait]
impl<T: OTSenderFactory + Send> MultiplicativeToAdditive for Sender<T, MulShare>
where
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue> + Send,
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
        id: String,
    ) -> Result<Vec<Self::FieldElement>, HomomorphicError> {
        self.convert(input, id).await
    }
}
