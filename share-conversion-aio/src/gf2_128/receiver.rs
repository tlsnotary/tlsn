//! This module implements the async IO receiver

use super::{
    recorder::{Recorder, Tape, Void},
    AddShare, Gf2ConversionChannel, Gf2_128ShareConvert, MulShare, VerifyTape,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};
use mpc_core::Block;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory, U: Gf2_128ShareConvert, V = Void> {
    /// Provides initialized OTs for the OT receiver
    receiver_factory: T,
    id: String,
    protocol: std::marker::PhantomData<U>,
    channel: Gf2ConversionChannel,
    recorder: V,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
        V: Gf2_128ShareConvert,
        W: Recorder<V>,
    > Receiver<T, V, W>
{
    /// Create a new receiver
    pub fn new(receiver_factory: T, id: String, channel: Gf2ConversionChannel) -> Self {
        Self {
            receiver_factory,
            id,
            protocol: std::marker::PhantomData,
            channel,
            recorder: W::default(),
            counter: 0,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&mut self, shares: &[u128]) -> Result<Vec<u128>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }
        let ot_number = shares.len() * 128;

        // Get choices for OT from shares
        let mut choices: Vec<bool> = Vec::with_capacity(ot_number);
        shares.iter().for_each(|x| {
            let share = V::new(*x).choices();
            choices.extend_from_slice(&share);
        });

        // Get an OT receiver from factory
        let mut ot_receiver = self
            .receiver_factory
            .new_receiver(format!("{}/{}/ot", &self.id, &self.counter), ot_number)
            .await?;

        self.counter += 1;
        let ot_output = ot_receiver.receive(&choices).await?;

        // Aggregate chunks of OTs to get back u128 values
        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| {
                V::from_sender_values(&chunk.iter().map(|x| x.inner()).collect::<Vec<u128>>())
                    .inner()
            })
            .collect();

        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<AddShare> + Send,
    > AdditiveToMultiplicative for Receiver<T, AddShare, V>
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from(input).await?;
        self.recorder.record_for_receiver(input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<MulShare> + Send,
    > MultiplicativeToAdditive for Receiver<T, MulShare, V>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from(input).await?;
        self.recorder.record_for_receiver(input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<T, U> VerifyTape for Receiver<T, U, Tape>
where
    T: OTReceiverFactory + Send,
    U: Gf2_128ShareConvert + Send,
{
    async fn verify_tape(mut self) -> Result<(), ShareConversionError> {
        let message = self.channel.next().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "stream closed unexpectedly",
        ))?;

        let (seed, sender_tape): ([u8; 32], Vec<u128>) = message.try_into()?;
        <Tape as Recorder<U>>::set_seed(&mut self.recorder, seed);
        <Tape as Recorder<U>>::record_for_sender(&mut self.recorder, &sender_tape);
        <Tape as Recorder<U>>::verify(&self.recorder)
    }
}
