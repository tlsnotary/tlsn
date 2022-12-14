//! This module implements the async IO sender

use super::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};
use crate::gf2_128::SendTape;
use crate::{
    gf2_128::recorder::{Recorder, Tape, Void},
    AdditiveToMultiplicative, ConversionChannel, ConversionMessage, MultiplicativeToAdditive,
    ShareConversionError,
};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

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
    channel: ConversionChannel<ChaCha12Rng, u128>,
    recorder: V,
}

impl<T, U, V> Sender<T, U, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    /// Creates a new sender
    pub fn new(
        sender_factory: T,
        id: String,
        channel: ConversionChannel<ChaCha12Rng, u128>,
    ) -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            sender_factory,
            id,
            protocol: std::marker::PhantomData,
            rng,
            channel,
            recorder: V::default(),
        }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        let mut local_shares = vec![];

        if shares.is_empty() {
            return Ok(local_shares);
        }

        let mut ot_shares = OTEnvelope::default();
        shares.iter().for_each(|share| {
            let share = U::new(*share);
            let (local, ot) = share.convert(&mut self.rng);
            local_shares.push(local.inner());
            ot_shares.extend(ot);
        });
        let mut ot_sender = self
            .sender_factory
            .new_sender(self.id.clone(), ot_shares.len())
            .await?;
        ot_sender.send(ot_shares.into()).await?;
        Ok(local_shares)
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
        let seed = self.recorder.seed;
        let sender_inputs = self.recorder.sender_inputs;

        let message = ConversionMessage {
            sender_tape: (seed, sender_inputs),
        };

        self.channel.send(message).await?;
        Ok(())
    }
}
