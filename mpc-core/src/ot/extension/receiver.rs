use aes::{cipher::generic_array::GenericArray, Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

use super::{ExtReceiveCore, ExtReceiverCoreError, ExtSenderPayload};
use crate::block::Block;
use crate::ot::base::{
    ReceiverSetup as BaseReceiverSetup, SenderPayload as BaseSenderPayload,
    SenderSetup as BaseSenderSetup,
};
use crate::ot::{SendCore, SenderCore};
use crate::utils;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum State {
    Initialized,
    BaseSetup,
    Setup,
    Complete,
}

pub struct ExtReceiverCore<R, C> {
    cipher: C,
    rng: R,
    state: State,
    base: Box<dyn SendCore>,
    seeds: Option<Vec<[Block; 2]>>,
    rngs: Option<Vec<[ChaCha12Rng; 2]>>,
    table: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExtReceiverSetup {
    pub ncols: usize,
    pub table: Vec<Vec<u8>>,
}

impl Default for ExtReceiverCore<ChaCha12Rng, Aes128> {
    fn default() -> Self {
        Self::new(
            ChaCha12Rng::from_entropy(),
            Aes128::new(GenericArray::from_slice(&[0u8; 16])),
            Box::new(SenderCore::default()),
        )
    }
}

impl<R: Rng + CryptoRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt> ExtReceiverCore<R, C> {
    pub fn new(rng: R, cipher: C, ot: Box<dyn SendCore>) -> Self {
        Self {
            rng,
            cipher,
            state: State::Initialized,
            base: ot,
            seeds: None,
            rngs: None,
            table: None,
        }
    }

    fn set_seeds(&mut self, seeds: Vec<[Block; 2]>) {
        let rngs: Vec<[ChaCha12Rng; 2]> = seeds
            .iter()
            .map(|k| {
                let k0: [u8; 16] = k[0].to_be_bytes();
                let k1: [u8; 16] = k[1].to_be_bytes();
                let k0: [u8; 32] = [k0, k0]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                let k1: [u8; 32] = [k1, k1]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                [ChaCha12Rng::from_seed(k0), ChaCha12Rng::from_seed(k1)]
            })
            .collect();
        self.seeds = Some(seeds);
        self.rngs = Some(rngs);
    }
}

impl<R: Rng + CryptoRng + SeedableRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>
    ExtReceiveCore for ExtReceiverCore<R, C>
{
    fn state(&self) -> State {
        self.state
    }

    fn base_setup(&mut self) -> Result<BaseSenderSetup, ExtReceiverCoreError> {
        Ok(self.base.setup())
    }

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError> {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(128);
        for i in 0..128 {
            seeds.push([Block::random(&mut self.rng), Block::random(&mut self.rng)]);
        }

        let base_send = self.base.send(&seeds.as_slice(), base_receiver_setup)?;

        self.set_seeds(seeds);
        self.state = State::BaseSetup;
        Ok(base_send)
    }

    fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<ExtReceiverSetup, ExtReceiverCoreError> {
        if self.state < State::BaseSetup {
            return Err(ExtReceiverCoreError::BaseOTNotSetup);
        }
        let r = utils::boolvec_to_u8vec(choice);
        let m = choice.len();
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; 128];
        let mut gs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; 128];

        let rngs = self
            .rngs
            .as_mut()
            .ok_or_else(|| ExtReceiverCoreError::BaseOTNotSetup)?;
        for j in 0..128 {
            rngs[j][0].fill_bytes(&mut ts[j]);
            rngs[j][1].fill_bytes(&mut gs[j]);
            gs[j] = gs[j]
                .iter()
                .zip(&ts[j])
                .zip(&r)
                .map(|((g, t), r)| *g ^ *t ^ *r)
                .collect();
        }
        self.table = Some(utils::transpose(&ts));
        self.state = State::Setup;

        Ok(ExtReceiverSetup { ncols, table: gs })
    }

    fn receive(
        &mut self,
        choice: &[bool],
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        if self.state < State::Setup {
            return Err(ExtReceiverCoreError::NotSetup);
        }
        let mut values: Vec<Block> = Vec::with_capacity(choice.len());
        let r = utils::boolvec_to_u8vec(choice);
        let ts = self
            .table
            .as_ref()
            .ok_or_else(|| ExtReceiverCoreError::NotSetup)?;

        for (j, b) in choice.iter().enumerate() {
            let t: [u8; 16] = ts[j].clone().try_into().unwrap();
            let t = Block::from(t);
            let y = if *b {
                payload.encrypted_values[j][1]
            } else {
                payload.encrypted_values[j][0]
            };
            let y = y ^ t.hash_tweak(&mut self.cipher, j);
            values.push(y);
        }
        self.state = State::Complete;

        Ok(values)
    }
}
