//! This module implements the async IO receiver

use super::{recorder::Tape, ReceiverConfig, ShareConversionChannel};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError, VerifyTape};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_ot::ObliviousReceive;
use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    AddShare, MulShare, ShareConvert,
};
use std::{marker::PhantomData, sync::Arc};

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<U, V, X>
where
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
{
    ot_receiver: Arc<dyn ObliviousReceive<bool, X> + Send + Sync>,
    config: ReceiverConfig,
    _protocol: PhantomData<U>,
    channel: ShareConversionChannel<V>,
    /// If a non-Void recorder was passed in, it will be used to record the "tape", ( see [Recorder::Tape])
    recorder: Option<Tape<V>>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<U, V, X> Receiver<U, V, X>
where
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
{
    /// Create a new receiver
    pub fn new(
        config: ReceiverConfig,
        ot_receiver: Arc<dyn ObliviousReceive<bool, X> + Send + Sync>,
        channel: ShareConversionChannel<V>,
    ) -> Self {
        let recorder = config.record().then(Tape::default);
        Self {
            ot_receiver,
            config,
            _protocol: PhantomData,
            channel,
            recorder,
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
            .receive(
                &format!("{}/{}/ot", &self.config.id(), &self.counter),
                choices,
            )
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
impl<V, X> AdditiveToMultiplicative<V> for Receiver<AddShare<V>, V, X>
where
    V: Field<BlockEncoding = X>,
{
    async fn a_to_m(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.record_for_receiver(&input, &output);
        }
        Ok(output)
    }
}

#[async_trait]
impl<V, X> MultiplicativeToAdditive<V> for Receiver<MulShare<V>, V, X>
where
    V: Field<BlockEncoding = X>,
{
    async fn m_to_a(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        let output = self.convert_from(&input).await?;
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.record_for_receiver(&input, &output);
        }
        Ok(output)
    }
}

#[async_trait]
impl<U, V, X> VerifyTape for Receiver<U, V, X>
where
    U: ShareConvert<Inner = V> + Send,
    V: Field<BlockEncoding = X>,
{
    async fn verify_tape(mut self) -> Result<(), ShareConversionError> {
        let Some(mut tape) = self.recorder.take() else {
            return Err(ShareConversionError::TapeNotConfigured);
        };

        let message = self.channel.next().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "stream closed unexpectedly",
        ))?;

        let ShareConversionMessage::SenderRecordings(SenderRecordings {
            seed,
            sender_inputs,
        }) = message;

        tape.set_seed(
            seed.try_into()
                .map_err(|_| ShareConversionError::InvalidSeed)?,
        );
        tape.record_for_sender(&sender_inputs);
        tape.verify::<U>()
    }
}
