//! This module implements the async IO sender

use super::{recorder::Tape, SenderConfig, ShareConversionChannel};
use crate::{
    ot::OTSendElement, AdditiveToMultiplicative, MultiplicativeToAdditive, SendTape,
    ShareConversionError,
};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    AddShare, MulShare, OTEnvelope, ShareConvert,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::{marker::PhantomData, sync::Arc};
use utils_aio::adaptive_barrier::AdaptiveBarrier;

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    ot_sender: Arc<dyn OTSendElement<F>>,
    config: SenderConfig,
    _protocol: PhantomData<T>,
    rng: ChaCha12Rng,
    channel: ShareConversionChannel<F>,
    /// If a non-[Void] recorder was passed in, it will be used to record the "tape", ( see [super::recorder::Tape])
    recorder: Option<Tape<F>>,
    /// A barrier at which this Sender must wait before revealing the tape to the receiver. Used when
    /// multiple parallel share conversion protocols need to agree when to reveal their tapes.
    barrier: Option<AdaptiveBarrier>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<T, F> Sender<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    /// Create a new sender
    pub fn new(
        config: SenderConfig,
        ot_sender: Arc<dyn OTSendElement<F>>,
        channel: ShareConversionChannel<F>,
        barrier: Option<AdaptiveBarrier>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        let recorder = config.record().then(|| Tape::new(rng.get_seed()));
        Self {
            ot_sender,
            config,
            _protocol: PhantomData,
            rng,
            channel,
            recorder,
            barrier,
            counter: 0,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&mut self, shares: &[F]) -> Result<Vec<F>, ShareConversionError> {
        let mut local_shares = Vec::with_capacity(shares.len());

        if shares.is_empty() {
            return Ok(local_shares);
        }

        // Prepare shares for OT and also create this party's converted shares
        let mut ot_shares = OTEnvelope::default();
        for share in shares {
            let share = T::new(*share);
            let (local, ot) = share.convert(&mut self.rng)?;
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        }

        // Send OT shares to the receiver and increment batch counter
        self.ot_sender
            .send(
                &format!("{}/{}/ot", &self.config.id(), &self.counter),
                ot_shares.into(),
            )
            .await?;
        self.counter += 1;

        Ok(local_shares)
    }
}

// Used for unit testing
#[cfg(test)]
impl<T, F> Sender<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    pub(crate) fn tape_mut(&mut self) -> &mut Tape<F> {
        self.recorder.as_mut().unwrap()
    }
}

#[async_trait]
impl<F> AdditiveToMultiplicative<F> for Sender<AddShare<F>, F>
where
    F: Field,
{
    async fn a_to_m(&mut self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.record_for_sender(&input)
        }
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<F> MultiplicativeToAdditive<F> for Sender<MulShare<F>, F>
where
    F: Field,
{
    async fn m_to_a(&mut self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.record_for_sender(&input)
        }
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<T, F> SendTape for Sender<T, F>
where
    T: ShareConvert<Inner = F> + Send,
    F: Field,
{
    async fn send_tape(mut self) -> Result<(), ShareConversionError> {
        let Some(tape) = self.recorder.take() else {
            return Err(ShareConversionError::TapeNotConfigured);
        };

        let message = SenderRecordings {
            seed: tape.seed.to_vec(),
            sender_inputs: tape.sender_inputs,
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
