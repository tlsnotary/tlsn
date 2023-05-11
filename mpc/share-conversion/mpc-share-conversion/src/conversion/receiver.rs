//! This module implements the async IO receiver

use super::{tape::Tape, ReceiverConfig, ShareConversionChannel};
use crate::{
    ot::OTReceiveElement, AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError,
    VerifyTape,
};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    AddShare, MulShare, ShareConvert,
};
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    ot_receiver: Arc<dyn OTReceiveElement<F>>,
    config: ReceiverConfig,
    channel: ShareConversionChannel<F>,
    state: Mutex<State<F>>,

    _protocol: PhantomData<T>,
}

struct State<F: Field> {
    tape: Option<Tape<F>>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
}

impl<T, F> Receiver<T, F>
where
    T: ShareConvert<Inner = F>,
    F: Field,
{
    /// Create a new receiver
    pub fn new(
        config: ReceiverConfig,
        ot_receiver: Arc<dyn OTReceiveElement<F>>,
        channel: ShareConversionChannel<F>,
    ) -> Self {
        let recorder = config.record().then(Tape::default);
        Self {
            ot_receiver,
            config,
            channel,
            state: Mutex::new(State {
                tape: recorder,
                counter: 0,
            }),
            _protocol: PhantomData,
        }
    }

    /// Converts a batch of shares using oblivious transfer
    async fn convert_from(&self, shares: &[F]) -> Result<Vec<F>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let ot_number = shares.len() * F::BIT_SIZE as usize;

        // Get choices for OT from shares
        let mut choices: Vec<bool> = Vec::with_capacity(ot_number);
        shares.iter().for_each(|x| {
            let share = T::new(*x).choices();
            choices.extend_from_slice(&share);
        });

        let counter = {
            let mut state = self.state.lock().unwrap();
            let counter = state.counter;
            state.counter += 1;
            counter
        };

        // Receive OT shares from the sender and increment batch counter
        let ot_output = self
            .ot_receiver
            .receive(&format!("{}/{}", &self.config.id(), &counter), choices)
            .await?;

        // Aggregate OTs to get back field elements from [Field::BlockEncoding]
        let field_elements: Vec<F> = ot_output
            .into_iter()
            .map(|ot_out| Into::into(ot_out))
            .collect();

        // Aggregate field elements representing a single field element to get the final output for
        // the receiver
        let converted_shares: Vec<F> = field_elements
            .chunks(F::BIT_SIZE as usize)
            .map(|elements| T::from_sender_values(elements).inner())
            .collect();

        if let Some(recorder) = self.state.lock().unwrap().tape.as_mut() {
            recorder.record_for_receiver(shares, &converted_shares);
        }

        Ok(converted_shares)
    }
}

#[async_trait]
impl<F> AdditiveToMultiplicative<F> for Receiver<AddShare<F>, F>
where
    F: Field,
{
    async fn a_to_m(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<F> MultiplicativeToAdditive<F> for Receiver<MulShare<F>, F>
where
    F: Field,
{
    async fn m_to_a(&self, input: Vec<F>) -> Result<Vec<F>, ShareConversionError> {
        self.convert_from(&input).await
    }
}

#[async_trait]
impl<T, F> VerifyTape for Receiver<T, F>
where
    T: ShareConvert<Inner = F> + Send,
    F: Field,
{
    async fn verify_tape(mut self) -> Result<(), ShareConversionError> {
        let mut state = self.state.into_inner().unwrap();

        let Some(mut tape) = state.tape.take() else {
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
        tape.verify::<T>()
    }
}
