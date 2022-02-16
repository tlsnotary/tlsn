use crate::block::Block;
//use crate::rng::{Rng, RngSeed};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};

pub struct BaseOTSender {
    private_key: Scalar,
    public_key: RistrettoPoint,
    counter: usize,
}

pub struct BaseOTSenderSetup {
    pub(super) public_key: RistrettoPoint,
}

pub struct BaseOTSenderSend {
    pub(super) encrypted_values: Vec<[Block; 2]>,
}

pub struct BaseOTReceiver {
    point_table: RistrettoBasepointTable,
    hashes: Option<Vec<Block>>,
    counter: usize,
}

pub struct BaseOTReceiverSetup {
    pub(super) keys: Vec<RistrettoPoint>,
}

pub struct BaseOTReceiverReceive {
    pub(super) values: Vec<Block>,
}

impl BaseOTSender {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let private_key = Scalar::random(rng);
        Self {
            private_key,
            public_key: &private_key * &RISTRETTO_BASEPOINT_TABLE,
            counter: 0,
        }
    }

    pub fn setup(&self) -> BaseOTSenderSetup {
        BaseOTSenderSetup {
            public_key: self.public_key,
        }
    }

    pub fn send(
        &mut self,
        inputs: &[[Block; 2]],
        receiver_setup: BaseOTReceiverSetup,
    ) -> BaseOTSenderSend {
        let ys = self.private_key * self.public_key;
        let encrypted_values: Vec<[Block; 2]> = inputs
            .iter()
            .zip(receiver_setup.keys)
            .enumerate()
            .map(|(i, (input, receiver_key))| {
                let tweak = self.counter + i;
                let yr = self.private_key * receiver_key;
                let k0 = Block::hash_point(&yr, i);
                let k1 = Block::hash_point(&(yr - ys), tweak);
                let c0 = k0 ^ input[0];
                let c1 = k1 ^ input[1];
                [c0, c1]
            })
            .collect();
        self.counter += encrypted_values.len();

        BaseOTSenderSend { encrypted_values }
    }
}

impl BaseOTReceiver {
    pub fn new(sender_setup: BaseOTSenderSetup) -> Self {
        Self {
            point_table: RistrettoBasepointTable::create(&sender_setup.public_key),
            hashes: None,
            counter: 0,
        }
    }

    pub fn setup<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        choice: &[bool],
    ) -> BaseOTReceiverSetup {
        let zero = &Scalar::zero() * &self.point_table;
        let one = &Scalar::one() * &self.point_table;
        let (keys, hashes): (Vec<RistrettoPoint>, Vec<Block>) = choice
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let tweak = self.counter + i;
                let x = Scalar::random(rng);
                let c = if *b { one } else { zero };
                let k = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                let h = Block::hash_point(&(&x * &self.point_table), tweak);
                (k, h)
            })
            .unzip();
        self.counter += choice.len();
        self.hashes = Some(hashes);

        BaseOTReceiverSetup { keys }
    }

    pub fn receive(&self, choice: &[bool], send: BaseOTSenderSend) -> BaseOTReceiverReceive {
        let hashes = self.hashes.as_ref().unwrap();
        let values = choice
            .iter()
            .zip(hashes)
            .zip(send.encrypted_values)
            .map(|((c, h), v)| *h ^ if *c { v[1] } else { v[0] })
            .collect();

        BaseOTReceiverReceive { values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_base_ot() {
        let mut s_rng = ChaCha12Rng::from_entropy();
        let mut r_rng = ChaCha12Rng::from_entropy();
        let mut sender = BaseOTSender::new(&mut s_rng);

        let sender_setup = sender.setup();
        let s_inputs = [
            [Block::new(0), Block::new(1)],
            [Block::new(2), Block::new(3)],
        ];

        let mut receiver = BaseOTReceiver::new(sender_setup);
        let choice = [false, true];

        let receiver_setup = receiver.setup(&mut r_rng, &choice);

        let send = sender.send(&s_inputs, receiver_setup);
        let receive = receiver.receive(&choice, send);
        assert_eq!(receive.values, [Block::new(0), Block::new(3)]);
    }
}
