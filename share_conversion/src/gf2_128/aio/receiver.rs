//! This module implements the async IO receiver

use super::{AddShare, Gf2_128ShareConvert, MulShare};
use crate::ShareConversionError;
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory, U: Gf2_128ShareConvert> {
    receiver_factory_control: T,
    share_type: std::marker::PhantomData<U>,
    id: String,
}

impl<
        T: OTReceiverFactory<Protocol = V> + Send,
        U: Gf2_128ShareConvert,
        V: ObliviousReceive<Choice = bool, Outputs = Vec<u128>>,
    > Receiver<T, U>
{
    /// Creates a new receiver
    pub fn new(receiver_factory_control: T, id: String) -> Self {
        Self {
            receiver_factory_control,
            share_type: std::marker::PhantomData,
            id,
        }
    }

    /// Convert the shares using oblivious transfer
    pub async fn convert(&mut self, shares: &[u128]) -> Result<Vec<u128>, ShareConversionError> {
        let mut out: Vec<<<T as OTReceiverFactory>::Protocol as ObliviousReceive>::Choice> = vec![];
        shares.iter().for_each(|x| {
            let share = U::new(*x).choices();
            out.extend_from_slice(&share);
        });
        let mut ot_receiver = self
            .receiver_factory_control
            .new_receiver(self.id.clone(), out.len() * 128)
            .await?;
        let ot_output = ot_receiver.receive(&out).await?;

        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| U::from_choice(chunk).inner())
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = V> + Send,
        V: ObliviousReceive<Choice = bool, Outputs = Vec<u128>> + Send,
    > AdditiveToMultiplicative for Receiver<T, AddShare>
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert(input).await
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = V> + Send,
        V: ObliviousReceive<Choice = bool, Outputs = Vec<u128>> + Send,
    > MultiplicativeToAdditive for Receiver<T, MulShare>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert(input).await
    }
}
