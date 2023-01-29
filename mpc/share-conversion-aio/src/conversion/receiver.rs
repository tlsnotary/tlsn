//! This module implements the async IO receiver

use super::{
    recorder::{Recorder, Tape, Void},
    ShareConversionChannel,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError, VerifyTape};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_aio::protocol::ot::{
    config::{OTReceiverConfig, OTReceiverConfigBuilder},
    OTFactoryError, ObliviousReceive,
};
use mpc_core::Block;
use share_conversion_core::{fields::Field, AddShare, MulShare, ShareConvert};
use std::marker::PhantomData;
use utils_aio::factory::AsyncFactory;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T, OT, U, V = Void>
where
    T: AsyncFactory<OT>,
    U: ShareConvert,
{
    /// Provides initialized OTs for the OT receiver
    receiver_factory: T,
    _ot: PhantomData<OT>,
    id: String,
    _protocol: PhantomData<U>,
    channel: ShareConversionChannel,
    /// If a non-Void recorder was passed in, it will be used to record the "tape", ( see [Recorder::Tape])
    recorder: V,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<T, OT, U, V> Receiver<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    OT: ObliviousReceive<bool, Block>,
    U: ShareConvert,
    V: Default,
{
    /// Create a new receiver
    pub fn new(receiver_factory: T, id: String, channel: ShareConversionChannel) -> Self {
        Self {
            receiver_factory,
            _ot: PhantomData,
            id,
            _protocol: PhantomData,
            channel,
            recorder: V::default(),
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
            .create(
                format!("{}/{}/ot", &self.id, &self.counter),
                OTReceiverConfigBuilder::default()
                    .count(ot_number)
                    .build()
                    .expect("OTReceiverConfig should be valid"),
            )
            .await?;

        self.counter += 1;
        let ot_output = ot_receiver.receive(choices).await?;

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
impl<T, OT, U, V> AdditiveToMultiplicative<V> for Receiver<T, OT, AddShare<V>, U>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    OT: ObliviousReceive<bool, Block> + Send,
    U: Recorder<AddShare<V>, V> + Send,
    V: Field,
{
    async fn a_to_m(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        self.recorder.record_for_receiver(&input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<T, OT, U, V> MultiplicativeToAdditive<V> for Receiver<T, OT, MulShare<V>, U>
where
    T: AsyncFactory<OT, Config = OTReceiverConfig, Error = OTFactoryError> + Send,
    OT: ObliviousReceive<bool, Block> + Send,
    U: Recorder<MulShare<V>, V> + Send,
    V: Field,
{
    async fn m_to_a(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        self.recorder.record_for_receiver(&input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<T, OT, U, V> VerifyTape for Receiver<T, OT, U, Tape<V>>
where
    T: AsyncFactory<OT> + Send,
    OT: ObliviousReceive<bool, Block> + Send,
    U: ShareConvert + Send,
    V: Field,
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
