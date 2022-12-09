//! This module implements the async IO sender

use super::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};
use crate::{
    recorder::{Recorder, Tape, Void},
    AdditiveToMultiplicative, ConversionChannel, ConversionMessage, MultiplicativeToAdditive,
    SendTape, ShareConversionError,
};
use async_trait::async_trait;
use futures::SinkExt;
use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// The sender for the conversion
///
/// Will be the OT sender
pub struct Sender<T, U = Void>
where
    T: OTSenderFactory,
{
    sender_factory: T,
    id: String,
    recorder: U,
}

impl<T, U> Sender<T, U>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Default,
{
    /// Creates a new sender
    pub fn new(sender_factory: T, id: String) -> Self {
        Self {
            sender_factory,
            id,
            recorder: U::default(),
        }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from<V: Gf2_128ShareConvert, W: Rng + SeedableRng + CryptoRng>(
        &mut self,
        shares: &[u128],
        rng: &mut W,
    ) -> Result<Vec<u128>, ShareConversionError> {
        let mut local_shares = vec![];

        if shares.is_empty() {
            return Ok(local_shares);
        }

        let mut ot_shares = OTEnvelope::default();
        shares.iter().for_each(|share| {
            let share = V::new(*share);
            let (local, ot) = share.convert(rng);
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
impl<T, U> AdditiveToMultiplicative for Sender<T, U>
where
    T: OTSenderFactory + Send,
    U: Recorder<ChaCha12Rng, u128>,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let mut rng = ChaCha12Rng::from_entropy();
        self.recorder.record_sender_input(rng.get_seed(), input);
        self.convert_from::<AddShare, _>(input, &mut rng).await
    }
}

#[async_trait]
impl<T, U> MultiplicativeToAdditive for Sender<T, U>
where
    T: OTSenderFactory + Send,
    U: Recorder<ChaCha12Rng, u128>,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let mut rng = ChaCha12Rng::from_entropy();
        self.recorder.record_sender_input(rng.get_seed(), input);
        self.convert_from::<MulShare, _>(input, &mut rng).await
    }
}

#[async_trait]
impl<T> SendTape<Tape<ChaCha12Rng, u128>, ChaCha12Rng, u128> for Sender<T, Tape<ChaCha12Rng, u128>>
where
    T: OTSenderFactory + Send,
{
    async fn send_tape(
        self,
        mut channel: ConversionChannel<ChaCha12Rng, u128>,
    ) -> Result<(), ShareConversionError> {
        let seeds = self.recorder.seeds;
        let sender_inputs = self.recorder.sender_inputs;
        let message = ConversionMessage {
            sender_tape: (seeds, sender_inputs),
        };

        channel.send(message).await?;
        Ok(())
    }
}
