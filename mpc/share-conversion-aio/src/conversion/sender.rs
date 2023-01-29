//! This module implements the async IO sender

use super::{
    recorder::{Recorder, Tape, Void},
    ShareConversionChannel,
};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, SendTape, ShareConversionError};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_aio::protocol::ot::{config::OTSenderConfig, OTFactoryError, ObliviousSend};
use mpc_core::{ot::config::OTSenderConfigBuilder, Block};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use share_conversion_core::{fields::Field, AddShare, MulShare, OTEnvelope, ShareConvert};
use std::marker::PhantomData;
use utils_aio::{adaptive_barrier::AdaptiveBarrier, factory::AsyncFactory};

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T, OT, U, V = Void>
where
    T: AsyncFactory<OT>,
    OT: ObliviousSend<[Block; 2]>,
    U: ShareConvert,
{
    /// Provides initialized OTs for the OT sender
    sender_factory: T,
    _ot: PhantomData<OT>,
    id: String,
    _protocol: PhantomData<U>,
    rng: ChaCha12Rng,
    channel: ShareConversionChannel,
    /// If a non-[Void] recorder was passed in, it will be used to record the "tape", ( see [super::recorder::Tape])
    recorder: V,
    /// A barrier at which this Sender must wait before revealing the tape to the receiver. Used when
    /// multiple parallel share conversion protocols need to agree when to reveal their tapes.
    barrier: Option<AdaptiveBarrier>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<T, OT, U, V> Sender<T, OT, U, V>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    OT: ObliviousSend<[Block; 2]>,
    U: ShareConvert,
    V: Default,
{
    /// Create a new sender
    pub fn new(
        sender_factory: T,
        id: String,
        channel: ShareConversionChannel,
        barrier: Option<AdaptiveBarrier>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            sender_factory,
            _ot: PhantomData,
            id,
            _protocol: PhantomData,
            rng,
            channel,
            recorder: V::default(),
            barrier,
            counter: 0,
        }
    }

    /// Converts a batch of shares using oblivious transfer
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
            .create(
                format!("{}/{}/ot", &self.id, &self.counter),
                OTSenderConfigBuilder::default()
                    .count(ot_shares.len() * 128)
                    .build()
                    .expect("OTSenderConfig should be valid"),
            )
            .await?;

        self.counter += 1;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
    }
}

// Used for unit testing
#[cfg(test)]
impl<T, OT, U, V> Sender<T, OT, U, Tape<V>>
where
    T: AsyncFactory<OT> + Send,
    OT: ObliviousSend<[Block; 2]>,
    U: ShareConvert,
    V: Field,
{
    pub fn tape_mut(&mut self) -> &mut Tape<V> {
        &mut self.recorder
    }
}

#[async_trait]
impl<T, OT, U, V> AdditiveToMultiplicative<V> for Sender<T, OT, AddShare<V>, U>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    OT: ObliviousSend<[Block; 2]> + Send,
    U: Recorder<AddShare<V>, V> + Send,
    V: Field,
{
    async fn a_to_m(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(&input);
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<T, OT, U, V> MultiplicativeToAdditive<V> for Sender<T, OT, MulShare<V>, U>
where
    T: AsyncFactory<OT, Config = OTSenderConfig, Error = OTFactoryError> + Send,
    OT: ObliviousSend<[Block; 2]> + Send,
    U: Recorder<MulShare<V>, V> + Send,
    V: Field,
{
    async fn m_to_a(&mut self, input: Vec<V>) -> Result<Vec<V>, ShareConversionError> {
        self.recorder.set_seed(self.rng.get_seed());
        self.recorder.record_for_sender(&input);
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<T, OT, U, V> SendTape for Sender<T, OT, U, Tape<V>>
where
    T: AsyncFactory<OT> + Send,
    OT: ObliviousSend<[Block; 2]> + Send,
    U: ShareConvert<Inner = V> + Send,
    V: Field,
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
