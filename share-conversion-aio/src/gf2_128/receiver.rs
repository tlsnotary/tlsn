//! This module implements the async IO receiver

use super::{AddShare, Gf2_128ShareConvert, MulShare};
use crate::{
    recorder::{Recorder, Void},
    AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};
use mpc_core::Block;
use rand_chacha::ChaCha12Rng;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory, U = Void> {
    receiver_factory: T,
    id: String,
    recorder: U,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
        V: Default,
    > Receiver<T, V>
{
    /// Creates a new receiver
    pub fn new(receiver_factory: T, id: String) -> Self {
        Self {
            receiver_factory,
            id,
            recorder: V::default(),
        }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from<W: Gf2_128ShareConvert>(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let mut choices: Vec<bool> = vec![];
        shares.iter().for_each(|x| {
            let share = W::new(*x).choices();
            choices.extend_from_slice(&share);
        });
        let mut ot_receiver = self
            .receiver_factory
            .new_receiver(self.id.clone(), choices.len() * 128)
            .await?;
        let ot_output = ot_receiver.receive(&choices).await?;

        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| {
                W::from_choice(&chunk.iter().map(|x| x.inner()).collect::<Vec<u128>>()).inner()
            })
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<ChaCha12Rng, u128>,
    > AdditiveToMultiplicative for Receiver<T, V>
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.recorder.record_receiver_input(input);
        let output = self.convert_from::<AddShare>(input).await?;
        self.recorder.record_receiver_output(&output);
        Ok(output)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<ChaCha12Rng, u128>,
    > MultiplicativeToAdditive for Receiver<T, V>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.recorder.record_receiver_input(input);
        let output = self.convert_from::<MulShare>(input).await?;
        self.recorder.record_receiver_output(&output);
        Ok(output)
    }
}
