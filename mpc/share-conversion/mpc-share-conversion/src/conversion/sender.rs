//! This module implements the async IO sender

use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use super::{tape::Tape, SenderConfig, ShareConversionChannel};
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
    state: Mutex<State<F>>,
    channel: ShareConversionChannel<F>,

    /// A barrier at which this Sender must wait before revealing the tape to the receiver. Used when
    /// multiple parallel share conversion protocols need to agree when to reveal their tapes.
    barrier: Option<AdaptiveBarrier>,

    _protocol: PhantomData<T>,
}

pub(crate) struct State<F: Field> {
    rng: ChaCha12Rng,
    pub(crate) tape: Option<Tape<F>>,
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
        let tape = config.record().then(|| Tape::new(rng.get_seed()));

        Self {
            ot_sender,
            config,
            channel,
            barrier,
            state: Mutex::new(State {
                rng,
                tape,
                counter: 0,
            }),
            _protocol: PhantomData,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&self, shares: &[F]) -> Result<Vec<F>, ShareConversionError> {
        let mut local_shares = Vec::with_capacity(shares.len());

        if shares.is_empty() {
            return Ok(local_shares);
        }

        let (ot_shares, counter) = {
            let mut state = self.state.lock().unwrap();

            if let Some(tape) = state.tape.as_mut() {
                tape.record_for_sender(shares);
            }

            let counter = state.counter;
            state.counter += 1;

            // Prepare shares for OT and also create this party's converted shares
            let mut ot_shares = OTEnvelope::default();
            for share in shares {
                let share = T::new(*share);
                let (local, ot) = share.convert(&mut state.rng)?;
                local_shares.push(local.inner());
                ot_shares.extend(ot);
            }

            (ot_shares, counter)
        };

        // Send OT shares to the receiver and increment batch counter
        self.ot_sender
            .send(
                &format!("{}/{}/ot", &self.config.id(), counter),
                ot_shares.into(),
            )
            .await?;

        Ok(local_shares)
    }
}

#[cfg(test)]
use std::ops::DerefMut;

// Used for unit testing
#[cfg(test)]
impl<T, F> Sender<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    pub(crate) fn state_mut(&mut self) -> impl DerefMut<Target = State<F>> + '_ {
        self.state.try_lock().unwrap()
    }
}

#[async_trait]
impl<F> AdditiveToMultiplicative<F> for Sender<AddShare<F>, F>
where
    F: Field,
{
    async fn a_to_m(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<F> MultiplicativeToAdditive<F> for Sender<MulShare<F>, F>
where
    F: Field,
{
    async fn m_to_a(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
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
        let mut state = self.state.into_inner().unwrap();

        let Some(mut tape) = state.tape.take() else {
            return Err(ShareConversionError::TapeNotConfigured);
        };

        let message = SenderRecordings {
            seed: tape.seed.to_vec(),
            sender_inputs: tape.sender_inputs,
        };

        if let Some(barrier) = self.barrier.take() {
            barrier.wait().await;
        }

        self.channel
            .send(ShareConversionMessage::SenderRecordings(message))
            .await?;

        Ok(())
    }
}
