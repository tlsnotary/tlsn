//! This module implements the async IO wrapper for the core logic.

use super::core::{Gf2_128HomomorphicConvert, MaskedPartialValue};
use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTError, OTFactoryError, OTSenderFactory, ObliviousSend};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use thiserror::Error;

pub struct GF2_128HomomorphicIOSender<T: OTSenderFactory, U: Gf2_128HomomorphicConvert> {
    sender_factory_control: T,
    share_type: std::marker::PhantomData<U>,
}

impl<T: OTSenderFactory, U: Gf2_128HomomorphicConvert> GF2_128HomomorphicIOSender<T, U> {
    pub fn new(sender_factory_control: T, share_type: U) -> Self {
        Self {
            sender_factory_control,
            share_type: std::marker::PhantomData,
        }
    }

    pub async fn convert(
        &mut self,
        shares: &[u128],
        id: String,
    ) -> Result<Vec<u128>, HomomorphicError>
    where
        <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<MaskedPartialValue>,
    {
        let shares = shares.iter().map(U::new);
        let (shares, ot_shares) = share.convert();
        let mut ot_sender = self
            .sender_factory_control
            .new_sender(id, ot_share.0.len())
            .await?;
        ot_sender.send(ot_share.into()).await?;
        Ok(share.inner())
    }
}

#[async_trait]
impl<T: OTSenderFactory, U: Gf2_128HomomorphicConvert> AdditiveToMultiplicative
    for GF2_128HomomorphicIOSender<T, U>
{
    type FieldElement = u128;

    async fn a_to_m(&mut self, input: &[Self::FieldElement]) -> Vec<Self::FieldElement> {
        let mut rng = ChaCha12Rng::from_entropy();
        let id = rng.gen::<u32>().to_string();

        self.convert(share, id)
    }
}

#[derive(Debug, Error)]
pub enum HomomorphicError {
    #[error("OTFactoryError: {0}")]
    OTFactoryError(#[from] OTFactoryError),
    #[error("OTError: {0}")]
    OTError(#[from] OTError),
}
