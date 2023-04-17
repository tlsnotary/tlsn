//! This module implements the async IO sender

use super::{
    recorder::{Recorder, Tape, Void},
    ShareConversionChannel,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, SendTape, ShareConversionError};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_ot::ObliviousSend;
use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    AddShare, MulShare, OTEnvelope, ShareConvert,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;
use utils_aio::adaptive_barrier::AdaptiveBarrier;

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<OT, U, V, X, W = Void>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    W: Recorder<U, V>,
{
    ot_sender: OT,
    id: String,
    _protocol: PhantomData<U>,
    rng: ChaCha12Rng,
    channel: ShareConversionChannel<V>,
    /// If a non-[Void] recorder was passed in, it will be used to record the "tape", ( see [super::recorder::Tape])
    recorder: W,
    /// A barrier at which this Sender must wait before revealing the tape to the receiver. Used when
    /// multiple parallel share conversion protocols need to agree when to reveal their tapes.
    barrier: Option<AdaptiveBarrier>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<OT, U, V, X, W> Sender<OT, U, V, X, W>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    W: Recorder<U, V>,
{
    /// Create a new sender
    pub fn new(
        ot_sender: OT,
        id: String,
        channel: ShareConversionChannel<V>,
        barrier: Option<AdaptiveBarrier>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            ot_sender,
            id,
            _protocol: PhantomData,
            rng,
            channel,
            recorder: W::default(),
            barrier,
            counter: 0,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&mut self, shares: &[V]) -> Result<Vec<V>, ShareConversionError> {
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

        // Send OT shares to the receiver and increment batch counter
        self.ot_sender
            .send(
                &format!("{}/{}/ot", &self.id, &self.counter),
                ot_shares.into(),
            )
            .await?;
        self.counter += 1;

        Ok(local_shares)
    }
}

// Used for unit testing
#[cfg(test)]
impl<OT, U, X, V> Sender<OT, U, V, X, Tape<V>>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
{
    pub fn tape_mut(&mut self) -> &mut Tape<V> {
        &mut self.recorder
    }
}

#[async_trait]
impl<OT, V, X, W> AdditiveToMultiplicative<V> for Sender<OT, AddShare<V>, V, X, W>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    V: Field<BlockEncoding = X>,
    W: Recorder<AddShare<V>, V> + Send,
    X: Send,
{
    async fn a_to_m(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(&input);
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<OT, V, X, W> MultiplicativeToAdditive<V> for Sender<OT, MulShare<V>, V, X, W>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    V: Field<BlockEncoding = X>,
    W: Recorder<MulShare<V>, V> + Send,
    X: Send,
{
    async fn m_to_a(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(&input);
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<OT, U, V, X> SendTape for Sender<OT, U, V, X, Tape<V>>
where
    OT: ObliviousSend<[X; 2]> + Send + Sync,
    U: ShareConvert<Inner = V> + Send,
    V: Field<BlockEncoding = X>,
{
    async fn send_tape(mut self) -> Result<(), ShareConversionError> {
        let message = SenderRecordings {
            seed: self.recorder.seed.to_vec(),
            sender_inputs: self.recorder.sender_inputs,
        };

        if let Some(barrier) = self.barrier {
            barrier.wait().await;
        }
        self.channel
            .send(ShareConversionMessage::SenderRecordings(message))
            .await?;
        Ok(())
    }
}
