//! Implementation of the oblivious transfer extension by Keller, Orsini, Scholl
//! https://eprint.iacr.org/2015/546

use super::base::{
    BaseOTReceiver, BaseOTReceiverSetup, BaseOTSender, BaseOTSenderSend, BaseOTSenderSetup,
};
use crate::block::Block;
use crate::utils;
use aes::{BlockCipher, BlockEncrypt};
use cipher::consts::U16;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

const K: usize = 40;
const NBASE: usize = 128;

pub struct OTSender<R, C> {
    rng: R,
    cipher: C,
    base_choice: Vec<bool>,
    base: BaseOTReceiver,
    seeds: Option<Vec<Block>>,
    rngs: Option<Vec<ChaCha12Rng>>,
    table: Option<Vec<Vec<u8>>>,
}

pub struct OTSenderSend {
    encrypted_values: Vec<[Block; 2]>,
}

pub struct OTReceiver<R, C> {
    cipher: C,
    rng: R,
    base: BaseOTSender,
    seeds: Option<Vec<[Block; 2]>>,
    rngs: Option<Vec<[ChaCha12Rng; 2]>>,
    table: Option<Vec<Vec<u8>>>,
}

pub struct OTReceiverSetup {
    table: Vec<Vec<u8>>,
}

pub struct OTReceiverReceive {
    values: Vec<Block>,
}

impl<R: Rng + CryptoRng + SeedableRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>
    OTSender<R, C>
{
    pub fn new(mut rng: R, cipher: C, base_sender_setup: BaseOTSenderSetup) -> Self {
        let mut base_choice = vec![0u8; NBASE / 8];
        rng.fill_bytes(&mut base_choice);
        Self {
            rng,
            cipher,
            base_choice: utils::u8vec_to_boolvec(&base_choice),
            base: BaseOTReceiver::new(base_sender_setup),
            seeds: None,
            rngs: None,
            table: None,
        }
    }

    pub fn base_setup(&mut self) -> BaseOTReceiverSetup {
        self.base.setup(&mut self.rng, &self.base_choice)
    }

    pub fn base_receive_seeds(&mut self, send: BaseOTSenderSend) {
        let receive = self.base.receive(&self.base_choice, send);
        self.set_seeds(receive.values);
    }

    pub fn set_seeds(&mut self, seeds: Vec<Block>) {
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

    pub fn extension_setup(&mut self, receiver_setup: OTReceiverSetup) {
        let ncols = receiver_setup.table[0].len() * 8;
        let us = receiver_setup.table;
        let mut qs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; NBASE];

        let rngs = self.rngs.as_mut().unwrap();
        for j in 0..NBASE {
            rngs[j].fill_bytes(&mut qs[j]);
            if self.base_choice[j] {
                qs[j] = qs[j].iter().zip(&us[j]).map(|(q, u)| *q ^ *u).collect();
            }
        }
        self.table = Some(utils::transpose(&qs));
    }

    pub fn send(&mut self, inputs: &[[Block; 2]]) -> OTSenderSend {
        let table = self.table.as_ref().unwrap();
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

        OTSenderSend { encrypted_values }
    }
}

impl<R: Rng + CryptoRng + SeedableRng, C: BlockCipher<BlockSize = U16> + BlockEncrypt>
    OTReceiver<R, C>
{
    pub fn new(mut rng: R, cipher: C) -> Self {
        let base = BaseOTSender::new(&mut rng);
        Self {
            rng,
            cipher,
            base,
            seeds: None,
            rngs: None,
            table: None,
        }
    }

    pub fn base_setup(&mut self) -> BaseOTSenderSetup {
        self.base.setup()
    }

    pub fn base_send_seeds(
        &mut self,
        base_receiver_setup: BaseOTReceiverSetup,
    ) -> BaseOTSenderSend {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(NBASE);
        for i in 0..NBASE {
            seeds.push([Block::random(&mut self.rng), Block::random(&mut self.rng)]);
        }

        let base_send = self.base.send(&seeds.as_slice(), base_receiver_setup);

        self.set_seeds(seeds);
        base_send
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

    pub fn extension_setup(&mut self, choice: &[bool]) -> OTReceiverSetup {
        let r = utils::boolvec_to_u8vec(choice);
        let m = choice.len();
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; NBASE];
        let mut gs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; NBASE];

        let rngs = self.rngs.as_mut().unwrap();
        for j in 0..NBASE {
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

        OTReceiverSetup { table: gs }
    }

    pub fn receive(&mut self, choice: &[bool], send: OTSenderSend) -> OTReceiverReceive {
        let mut values: Vec<Block> = Vec::with_capacity(choice.len());
        let r = utils::boolvec_to_u8vec(choice);
        let ts = self.table.as_ref().unwrap();

        for (j, b) in choice.iter().enumerate() {
            let t: [u8; 16] = ts[j].clone().try_into().unwrap();
            let t = Block::from(t);
            let y = send.encrypted_values[j];
            let y = if *b { y[1] } else { y[0] };
            let y = y ^ t.hash_tweak(&mut self.cipher, j);
            values.push(y);
        }

        OTReceiverReceive { values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::u8vec_to_boolvec;
    use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
    use aes::Aes128;
    use rand::{CryptoRng, Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_ot() {
        let s_rng = ChaCha12Rng::from_entropy();
        let s_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let r_rng = ChaCha12Rng::from_entropy();
        let r_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let mut receiver = OTReceiver::new(r_rng, r_cipher);
        let base_sender_setup = receiver.base_setup();

        let mut sender = OTSender::new(s_rng, s_cipher, base_sender_setup);
        let base_receiver_setup = sender.base_setup();

        let send_seeds = receiver.base_send_seeds(base_receiver_setup);
        sender.base_receive_seeds(send_seeds);

        let mut choice = vec![0u8; 2];
        let mut rng = ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let inputs: Vec<[Block; 2]> = (0..16)
            .map(|i| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();

        let receiver_setup = receiver.extension_setup(&choice);
        sender.extension_setup(receiver_setup);

        let send = sender.send(&inputs);
        let receive = receiver.receive(&choice, send);

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive.values);
    }

    #[test]
    fn test_base_setup() {
        let s_rng = ChaCha12Rng::from_entropy();
        let s_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let r_rng = ChaCha12Rng::from_entropy();
        let r_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let mut receiver = OTReceiver::new(r_rng, r_cipher);
        let base_sender_setup = receiver.base_setup();

        let mut sender = OTSender::new(s_rng, s_cipher, base_sender_setup);
        let base_receiver_setup = sender.base_setup();

        let send_seeds = receiver.base_send_seeds(base_receiver_setup);
        sender.base_receive_seeds(send_seeds);

        let inputs = receiver.seeds.unwrap();
        let choice = sender.base_choice;
        let received = sender.seeds.unwrap();
        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice.iter())
            .map(|(input, choice)| input[*choice as usize])
            .collect();
        assert_eq!(expected, received);
    }

    #[test]
    fn test_rngs() {
        let s_rng = ChaCha12Rng::from_entropy();
        let s_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let r_rng = ChaCha12Rng::from_entropy();
        let r_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let mut receiver = OTReceiver::new(r_rng, r_cipher);
        let base_sender_setup = receiver.base_setup();

        let mut sender = OTSender::new(s_rng, s_cipher, base_sender_setup);
        let base_receiver_setup = sender.base_setup();

        let send_seeds = receiver.base_send_seeds(base_receiver_setup);
        sender.base_receive_seeds(send_seeds);

        let receiver_rngs = receiver.rngs.unwrap();
        let mut receiver_chosen_rngs: Vec<ChaCha12Rng> = receiver_rngs
            .into_iter()
            .zip(sender.base_choice.iter())
            .map(|(rngs, choice)| rngs[*choice as usize].clone())
            .collect();
        let mut sender_rngs = sender.rngs.unwrap();

        for i in 0..NBASE {
            let mut s = vec![0u8; 16];
            let mut r = vec![0u8; 16];
            sender_rngs[i].fill_bytes(&mut s);
            receiver_chosen_rngs[i].fill_bytes(&mut r);
            assert_eq!(s, r);
        }
    }
}
