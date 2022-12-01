//! This module implements the async IO receiver for the core logic.
use super::{AddShare, Gf2_128HomomorphicConvert, MulShare};
use crate::HomomorphicError;
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};

pub struct Receiver<T: OTReceiverFactory, U: Gf2_128HomomorphicConvert> {
    receiver_factory_control: T,
    share_type: std::marker::PhantomData<U>,
}

impl<T: OTReceiverFactory, U: Gf2_128HomomorphicConvert> Receiver<T, U>
where
    T: Send,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice: Sync + Clone,
    Vec<<<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice>: From<u128>,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Outputs: Into<Vec<u128>>,
{
    pub fn new(receiver_factory_control: T) -> Self {
        Self {
            receiver_factory_control,
            share_type: std::marker::PhantomData,
        }
    }

    pub async fn convert(
        &mut self,
        shares: &[u128],
        id: String,
    ) -> Result<Vec<u128>, HomomorphicError> {
        let mut out: Vec<<<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice> = vec![];
        shares.iter().for_each(|x| {
            let share: Vec<_> = From::from(*x);
            out.extend_from_slice(&share);
        });
        let mut ot_receiver = self
            .receiver_factory_control
            .new_receiver(id, out.len() * 128)
            .await?;
        let ot_output = ot_receiver.receive(&out).await?.into();

        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| U::from_choice(chunk).inner())
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<T: OTReceiverFactory + Send> AdditiveToMultiplicative for Receiver<T, AddShare>
where
    T: Send,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice: Sync + Clone,
    Vec<<<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice>: From<u128> + Send,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Outputs: Into<Vec<u128>>,
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
impl<T: OTReceiverFactory + Send> MultiplicativeToAdditive for Receiver<T, MulShare>
where
    T: Send,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice: Sync + Clone,
    Vec<<<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice>: From<u128> + Send,
    <<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Outputs: Into<Vec<u128>>,
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
