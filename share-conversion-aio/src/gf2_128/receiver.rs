//! This module implements the async IO receiver

use super::{AddShare, Gf2_128ShareConvert, MulShare};
use crate::gf2_128::VerifyTape;
use crate::{
    gf2_128::recorder::{Recorder, Tape, Void},
    AdditiveToMultiplicative, ConversionChannel, MultiplicativeToAdditive, ShareConversionError,
};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};
use mpc_core::Block;
use rand_chacha::ChaCha12Rng;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory, U: Gf2_128ShareConvert, V = Void> {
    receiver_factory: T,
    id: String,
    protocol: std::marker::PhantomData<U>,
    rng: ChaCha12Rng,
    channel: ConversionChannel<ChaCha12Rng, u128>,
    recorder: V,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
        V: Gf2_128ShareConvert,
        W: Recorder<V>,
    > Receiver<T, U, V>
{
    /// Creates a new receiver
    pub fn new(
        receiver_factory: T,
        id: String,
        channel: ConversionChannel<ChaCha12Rng, u128>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            receiver_factory,
            id,
            protocol: std::marker::PhantomData,
            rng,
            channel,
            recorder: W::default(),
        }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from(
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
                V::from_choice(&chunk.iter().map(|x| x.inner()).collect::<Vec<u128>>()).inner()
            })
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Gf2_128ShareConvert,
        W: Recorder<AddShare>,
    > AdditiveToMultiplicative for Receiver<T, V, W>
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from(input).await?;
        self.recorder.record_for_receiver(input, output);
        Ok(output)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Gf2_128ShareConvert,
        W: Recorder<AddShare>,
    > MultiplicativeToAdditive for Receiver<T, V, W>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from(input).await?;
        self.recorder.record_for_receiver(input, output);
        Ok(output)
    }
}

#[async_trait]
impl<T> VerifyTape<Tape<ChaCha12Rng, u128>, ChaCha12Rng, u128>
    for Receiver<T, Tape<ChaCha12Rng, u128>>
where
    T: OTReceiverFactory + Send,
{
    async fn verify_tape(mut self) -> Result<bool, ShareConversionError> {
        let (sender_seeds, sender_values) = self
            .channel
            .next()
            .await
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stream closed unexpectedly",
            ))?
            .sender_tape;
        self.recorder.add_sender_inputs(sender_seeds, sender_values);

        // TODO: add verification
        // Current problem is that we do not know if AdditiveShares or MultiplicativeShares are
        // present
        todo!()
    }
}
