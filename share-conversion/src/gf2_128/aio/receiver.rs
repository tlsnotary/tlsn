//! This module implements the async IO receiver

use super::{AddShare, Gf2_128ShareConvert, MulShare};
use crate::ShareConversionError;
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory> {
    receiver_factory_control: T,
    id: String,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<u128>>,
    > Receiver<T>
{
    /// Creates a new receiver
    pub fn new(receiver_factory_control: T, id: String) -> Self {
        Self {
            receiver_factory_control,
            id,
        }
    }

    /// Convert the shares using oblivious transfer
    pub async fn convert<V: Gf2_128ShareConvert>(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let mut choices: Vec<bool> = vec![];
        shares.iter().for_each(|x| {
            let share = V::new(*x).choices();
            choices.extend_from_slice(&share);
        });
        let mut ot_receiver = self
            .receiver_factory_control
            .new_receiver(self.id.clone(), choices.len() * 128)
            .await?;
        let ot_output = ot_receiver.receive(&choices).await?;

        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| V::from_choice(chunk).inner())
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<u128>> + Send,
    > AdditiveToMultiplicative for Receiver<T>
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
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<u128>> + Send,
    > MultiplicativeToAdditive for Receiver<T>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.convert::<MulShare>(input).await
    }
}
