use aes::{cipher::generic_array::GenericArray, Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

use super::{ExtReceiverSetup, ExtSendCore, ExtSenderCoreError};
use crate::block::Block;
use crate::ot::base::{
    ReceiverSetup as BaseReceiverSetup, SenderPayload as BaseSenderPayload,
    SenderSetup as BaseSenderSetup,
};
use crate::ot::{ReceiveCore, ReceiverCore};
use crate::utils;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum State {
    Initialized,
    BaseSetup,
    Setup,
    Complete,
}

pub struct ExtSenderCore<C, OT> {
    cipher: C,
    state: State,
    base_choice: Vec<bool>,
    base: OT,
    seeds: Option<Vec<Block>>,
    rngs: Option<Vec<ChaCha12Rng>>,
    table: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExtSenderPayload {
    pub encrypted_values: Vec<[Block; 2]>,
}

impl Default for ExtSenderCore<Aes128, ReceiverCore<ChaCha12Rng>> {
    fn default() -> Self {
        Self::new(
            &mut ChaCha12Rng::from_entropy(),
            Aes128::new(GenericArray::from_slice(&[0u8; 16])),
            ReceiverCore::default(),
        )
    }
}

impl<C: BlockCipher<BlockSize = U16> + BlockEncrypt, OT: ReceiveCore> ExtSenderCore<C, OT> {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, cipher: C, ot: OT) -> Self {
        let mut base_choice = vec![0u8; 128 / 8];
        rng.fill_bytes(&mut base_choice);
        Self {
            cipher,
            state: State::Initialized,
            base_choice: utils::u8vec_to_boolvec(&base_choice),
            base: ot,
            seeds: None,
            rngs: None,
            table: None,
        }
    }

    fn set_seeds(&mut self, seeds: Vec<Block>) {
        let rngs: Vec<ChaCha12Rng> = seeds
            .iter()
            .map(|k| {
                let k: [u8; 16] = k.to_be_bytes();
                let k: [u8; 32] = [k, k]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                ChaCha12Rng::from_seed(k)
            })
            .collect();
        self.seeds = Some(seeds);
        self.rngs = Some(rngs);
    }
}

impl<C: BlockCipher<BlockSize = U16> + BlockEncrypt, OT: ReceiveCore> ExtSendCore
    for ExtSenderCore<C, OT>
{
    fn state(&self) -> State {
        self.state
    }

    fn base_setup(
        &mut self,
        base_sender_setup: BaseSenderSetup,
    ) -> Result<BaseReceiverSetup, ExtSenderCoreError> {
        Ok(self.base.setup(&self.base_choice, base_sender_setup)?)
    }

    fn base_receive(&mut self, payload: BaseSenderPayload) -> Result<(), ExtSenderCoreError> {
        let receive = self.base.receive(&self.base_choice, payload)?;
        self.set_seeds(receive);
        self.state = State::BaseSetup;
        Ok(())
    }

    fn extension_setup(
        &mut self,
        receiver_setup: ExtReceiverSetup,
    ) -> Result<(), ExtSenderCoreError> {
        if self.state < State::BaseSetup {
            return Err(ExtSenderCoreError::BaseOTNotSetup);
        }
        let ncols = receiver_setup.table[0].len() * 8;
        let us = receiver_setup.table;
        let mut qs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; 128];

        let rngs = self
            .rngs
            .as_mut()
            .ok_or_else(|| ExtSenderCoreError::BaseOTNotSetup)?;

        for j in 0..128 {
            rngs[j].fill_bytes(&mut qs[j]);
            if self.base_choice[j] {
                qs[j] = qs[j].iter().zip(&us[j]).map(|(q, u)| *q ^ *u).collect();
            }
        }
        self.table = Some(utils::transpose(&qs));
        self.state = State::Setup;
        Ok(())
    }

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        if self.state < State::Setup {
            return Err(ExtSenderCoreError::NotSetup);
        }
        let table = self
            .table
            .as_ref()
            .ok_or_else(|| ExtSenderCoreError::NotSetup)?;

        let mut encrypted_values: Vec<[Block; 2]> = Vec::with_capacity(table.len());

        let base_choice: [u8; 16] = utils::boolvec_to_u8vec(&self.base_choice)
            .try_into()
            .unwrap();
        let delta = Block::from(base_choice);
        for (j, input) in inputs.iter().enumerate() {
            let q: [u8; 16] = table[j].clone().try_into().unwrap();
            let q = Block::from(q);
            let y0 = q.hash_tweak(&mut self.cipher, j) ^ input[0];
            let y1 = (q ^ delta).hash_tweak(&mut self.cipher, j) ^ input[1];
            encrypted_values.push([y0, y1]);
        }
        self.state = State::Complete;

        Ok(ExtSenderPayload { encrypted_values })
    }
}
