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
        let mut qs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; NBASE];

        let rngs = self.rngs.as_mut().unwrap();
        for j in 0..NBASE {
            let b = &self.base_choice[j];
            let mut q = &mut qs[j];
            rngs[j].fill_bytes(&mut q);
            let q_: Vec<u8> = q
                .iter()
                .zip(&receiver_setup.table[j])
                .map(|(q, u)| *q ^ if *b { *u } else { 0 })
                .collect();
            qs[j] = q_;
        }
        self.table = Some(utils::transpose(&qs));
    }

    pub fn send(&mut self, inputs: &[[Block; 2]]) -> OTSenderSend {
        let table = self.table.as_ref().unwrap();
        let mut encrypted_values: Vec<[Block; 2]> = Vec::with_capacity(table.len());

        let base_choice: [u8; 16] = utils::boolvec_to_u8vec(&self.base_choice)
            .try_into()
            .unwrap();
        let base_choice = Block::from(base_choice);
        for (j, input) in inputs.iter().enumerate() {
            let q: [u8; 16] = table[j].clone().try_into().unwrap();
            let q = Block::from(q);
            let y0 = q.hash_tweak(&mut self.cipher, j) ^ input[0];
            let q = q ^ base_choice;
            let y1 = q.hash_tweak(&mut self.cipher, j) ^ input[1];
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
        let mut gs: Vec<Vec<u8>> = Vec::with_capacity(NBASE);

        let rngs = self.rngs.as_mut().unwrap();
        let mut g = vec![0u8; ncols / 8];
        for j in 0..NBASE {
            let mut t = &mut ts[j];
            rngs[j][0].fill_bytes(&mut t);
            rngs[j][1].fill_bytes(&mut g);
            g = g
                .iter()
                .zip(t)
                .zip(&r)
                .map(|((g, t), r)| *g ^ *t ^ *r)
                .collect();
            gs.push(g.clone());
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

        let choice = [false, true, false, true];
        let receiver_setup = receiver.extension_setup(&choice);
        sender.extension_setup(receiver_setup);

        let inputs = [[Block::new(123), Block::new(456)]; 4];
        let send = sender.send(&inputs);
        let receive = receiver.receive(&choice, send);

        let expected: Vec<Block> = inputs
            .iter()
            .zip(choice)
            .map(|(input, choice)| input[choice as usize])
            .collect();

        assert_eq!(expected, receive.values);
    }
}
