//! This module implements the async IO receiver

use super::{AddShare, Gf2_128ShareConvert, MulShare};
use crate::{
    recorder::{Recorder, Tape, Void},
    AdditiveToMultiplicative, ConversionChannel, MultiplicativeToAdditive, ShareConversionError,
    VerifyTape,
};
use async_trait::async_trait;
use futures::StreamExt;
use mpc_aio::protocol::ot::{OTReceiverFactory, ObliviousReceive};
use mpc_core::Block;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha12Rng;

/// The receiver for the conversion
///
/// Will be the OT receiver
pub struct Receiver<T: OTReceiverFactory, U = Void> {
    receiver_factory: T,
    id: String,
    recorder: U,
}

impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>>,
        V: Default,
    > Receiver<T, V>
{
    /// Creates a new receiver
    pub fn new(receiver_factory: T, id: String) -> Self {
        Self {
            receiver_factory,
            id,
            recorder: V::default(),
        }
    }

    /// Convert the shares using oblivious transfer
    pub(crate) async fn convert_from<W: Gf2_128ShareConvert>(
        &mut self,
        shares: &[u128],
    ) -> Result<Vec<u128>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let mut choices: Vec<bool> = vec![];
        shares.iter().for_each(|x| {
            let share = W::new(*x).choices();
            choices.extend_from_slice(&share);
        });
        let mut ot_receiver = self
            .receiver_factory
            .new_receiver(self.id.clone(), choices.len() * 128)
            .await?;
        let ot_output = ot_receiver.receive(&choices).await?;

        let converted_shares = ot_output
            .chunks(128)
            .map(|chunk| {
                W::from_choice(&chunk.iter().map(|x| x.inner()).collect::<Vec<u128>>()).inner()
            })
            .collect();
        Ok(converted_shares)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<ChaCha12Rng, u128> + Default,
    > AdditiveToMultiplicative for Receiver<T, V>
{
    type FieldElement = u128;

    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from::<MulShare>(input).await?;
        self.recorder
            .record_verifier(Box::new(|rng: ChaCha12Rng, sender_input: Vec<u128>| {
                verify::<_, AddShare>(sender_input, rng, input.to_vec(), output.clone())
            }));
        Ok(output)
    }
}

#[async_trait]
impl<
        T: OTReceiverFactory<Protocol = U> + Send,
        U: ObliviousReceive<Choice = bool, Outputs = Vec<Block>> + Send,
        V: Recorder<ChaCha12Rng, u128> + Default,
    > MultiplicativeToAdditive for Receiver<T, V>
{
    type FieldElement = u128;

    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError> {
        let output = self.convert_from::<MulShare>(input).await?;
        self.recorder
            .record_verifier(Box::new(|rng: ChaCha12Rng, sender_input: Vec<u128>| {
                verify::<_, MulShare>(sender_input, rng, input.to_vec(), output.clone())
            }));
        Ok(output)
    }
}

#[async_trait]
impl<T> VerifyTape<Tape<ChaCha12Rng, u128>, ChaCha12Rng, u128>
    for Receiver<T, Tape<ChaCha12Rng, u128>>
where
    T: OTReceiverFactory + Send,
{
    async fn verify_tape(
        mut self,
        mut channel: ConversionChannel<ChaCha12Rng, u128>,
    ) -> Result<bool, ShareConversionError> {
        let (sender_seeds, sender_values) = channel
            .next()
            .await
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stream closed unexpectedly",
            ))?
            .sender_tape;
        self.recorder.add_sender_inputs(sender_seeds, sender_values);

        // TODO: add verification
        // Current problem is that we do not know if AdditiveShares or MultiplicativeShares are
        // present
        todo!()
    }
}

fn verify<R: Rng + CryptoRng, T: Gf2_128ShareConvert>(
    sender_inputs: Vec<u128>,
    rng: R,
    receiver_inputs: Vec<u128>,
    expected_outputs: Vec<u128>,
) -> bool {
    for ((s_input, r_input), expected) in
        std::iter::zip(sender_inputs, receiver_inputs).zip(expected_outputs)
    {
        let (_, ot_envelope) = T::new(s_input).convert(&mut rng);
        let choices = T::new(r_input).choices();

        let mut ot_output: Vec<u128> = vec![0; 128];
        for (k, number) in ot_output.iter_mut().enumerate() {
            let bit = choices[k] as u128;
            *number = (bit * ot_envelope.1[k]) ^ ((bit ^ 1) * ot_envelope.0[k]);
        }
        let converted = T::Output::from_choice(&ot_output);
        if converted.inner() != expected {
            return false;
        }
    }
    true
}
