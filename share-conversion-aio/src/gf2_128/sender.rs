//! This module implements the async IO sender

use super::{
    recorder::{Recorder, Tape, Void},
    AddShare, Gf2ConversionChannel, Gf2_128ShareConvert, MulShare, OTEnvelope, SendTape,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use utils_aio::adaptive_barrier::AdaptiveBarrier;

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T, U, V = Void>
where
    T: OTSenderFactory,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    sender_factory: T,
    id: String,
    protocol: std::marker::PhantomData<U>,
    rng: ChaCha12Rng,
    channel: Gf2ConversionChannel,
    recorder: V,
    barrier: Option<AdaptiveBarrier>,
    counter: usize,
}

impl<T, U, V> Sender<T, U, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    /// Create a new sender
    pub fn new(
        sender_factory: T,
        id: String,
        channel: Gf2ConversionChannel,
        barrier: Option<AdaptiveBarrier>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            sender_factory,
            id,
            protocol: std::marker::PhantomData,
            rng,
            channel,
            recorder: V::default(),
            barrier,
            counter: 0,
        }
    }

    /// Convert the shares using oblivious transfer
    async fn convert_from(&mut self, shares: &[u128]) -> Result<Vec<u128>, ShareConversionError> {
        let mut local_shares = Vec::with_capacity(shares.len());

        if shares.is_empty() {
            return Ok(local_shares);
        }

        // Prepare shares for OT and also create this party's converted shares
        let mut ot_shares = OTEnvelope::default();
        for share in shares {
            let share = U::new(*share);
            let (local, ot) = share.convert(&mut self.rng)?;
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        }

        // Get an OT sender from factory
        let mut ot_sender = self
            .sender_factory
            .new_sender(
                format!("{}/{}/ot", &self.id, &self.counter),
                ot_shares.len(),
            )
            .await?;

        self.counter += 1;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
    }
}

// Used for unit testing
#[cfg(test)]
impl<T, U> Sender<T, U, Tape>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert,
{
    pub fn tape_mut(&mut self) -> &mut Tape {
        &mut self.recorder
    }
}

#[async_trait]
impl<T, V> AdditiveToMultiplicative for Sender<T, AddShare, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    V: Recorder<AddShare> + Send,
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(input);
        self.convert_from(input).await
    }
}

#[async_trait]
impl<T, V> MultiplicativeToAdditive for Sender<T, MulShare, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    V: Recorder<MulShare> + Send,
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(input);
        self.convert_from(input).await
    }
}

#[async_trait]
impl<T, U> SendTape for Sender<T, U, Tape>
where
    T: OTSenderFactory + Send,
    U: Gf2_128ShareConvert + Send,
{
    async fn send_tape(mut self) -> Result<(), ShareConversionError> {
        let message = (self.recorder.seed, self.recorder.sender_inputs).into();

        if let Some(barrier) = self.barrier {
            barrier.wait().await;
        }
        self.channel.send(message).await?;
        Ok(())
    }
}
