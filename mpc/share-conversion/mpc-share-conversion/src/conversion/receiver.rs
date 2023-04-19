//! This module implements the async IO receiver

use super::{
    recorder::{Recorder, Tape, Void},
    ShareConversionChannel,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError, VerifyTape};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_ot::ObliviousReceive;
use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    AddShare, MulShare, ShareConvert,
};
use std::marker::PhantomData;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<OT, U, V, X, W = Void>
where
    OT: ObliviousReceive<bool, X> + Send + Sync,
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    W: Recorder<U, V>,
{
    ot_receiver: OT,
    id: String,
    _protocol: PhantomData<U>,
    channel: ShareConversionChannel<V>,
    /// If a non-Void recorder was passed in, it will be used to record the "tape", ( see [Recorder::Tape])
    recorder: W,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<OT, U, V, X, W> Receiver<OT, U, V, X, W>
where
    OT: ObliviousReceive<bool, X> + Send + Sync,
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    W: Recorder<U, V>,
{
    /// Create a new receiver
    pub fn new(ot_receiver: OT, id: String, channel: ShareConversionChannel<V>) -> Self {
        Self {
            ot_receiver,
            id,
            _protocol: PhantomData,
            channel,
            recorder: W::default(),
            counter: 0,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&mut self, shares: &[V]) -> Result<Vec<V>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }
        let ot_number = shares.len() * V::BIT_SIZE as usize;

        // Get choices for OT from shares
        let mut choices: Vec<bool> = Vec::with_capacity(ot_number);
        shares.iter().for_each(|x| {
            let share = U::new(*x).choices();
            choices.extend_from_slice(&share);
        });

        // Receive OT shares from the sender and increment batch counter
        let ot_output = self
            .ot_receiver
            .receive(&format!("{}/{}/ot", &self.id, &self.counter), choices)
            .await?;
        self.counter += 1;

        // Aggregate OTs to get back field elements from [Field::BlockEncoding]
        let field_elements: Vec<V> = ot_output
            .into_iter()
            .map(|ot_out| Into::into(ot_out))
            .collect();

        // Aggregate field elements representing a single field element to get the final output for
        // the receiver
        let converted_shares: Vec<V> = field_elements
            .chunks(V::BIT_SIZE as usize)
            .map(|elements| U::from_sender_values(elements).inner())
            .collect();

        Ok(converted_shares)
    }
}

#[async_trait]
impl<OT, V, X, W> AdditiveToMultiplicative<V> for Receiver<OT, AddShare<V>, V, X, W>
where
    OT: ObliviousReceive<bool, X> + Send + Sync,
    V: Field<BlockEncoding = X>,
    W: Recorder<AddShare<V>, V> + Send,
{
    async fn a_to_m(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        self.recorder.record_for_receiver(&input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<OT, V, X, W> MultiplicativeToAdditive<V> for Receiver<OT, MulShare<V>, V, X, W>
where
    OT: ObliviousReceive<bool, X> + Send + Sync,
    V: Field<BlockEncoding = X>,
    W: Recorder<MulShare<V>, V> + Send,
{
    async fn m_to_a(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        self.recorder.record_for_receiver(&input, &output);
        Ok(output)
    }
}

#[async_trait]
impl<OT, U, V, X> VerifyTape for Receiver<OT, U, V, X, Tape<V>>
where
    OT: ObliviousReceive<bool, X> + Send + Sync,
    U: ShareConvert<Inner = V> + Send,
    V: Field<BlockEncoding = X>,
{
    async fn verify_tape(mut self) -> Result<(), ShareConversionError> {
        let message = self.channel.next().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "stream closed unexpectedly",
        ))?;

        let ShareConversionMessage::SenderRecordings(SenderRecordings {
            seed,
            sender_inputs,
        }) = message;

        <Tape<V> as Recorder<U, V>>::set_seed(
            &mut self.recorder,
            seed.try_into()
                .expect("Seed does not fit into 32 byte array"),
        );
        <Tape<V> as Recorder<U, V>>::record_for_sender(&mut self.recorder, &sender_inputs);
        <Tape<V> as Recorder<U, V>>::verify(&self.recorder)
    }
}
