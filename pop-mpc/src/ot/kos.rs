//! Implementation of the oblivious transfer extension by Keller, Orsini, Scholl
//! https://eprint.iacr.org/2015/546

use crate::block::Block;
//use crate::rng::{Rng, RngSeed};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha12Rng;

const K: usize = 40;
const ROWS: usize = 128;

pub struct BaseOTSender {
    y: Scalar,
    s: RistrettoPoint,
    counter: u128,
}

pub struct OTSetupSender {
    pub s: RistrettoPoint,
}

pub struct OTSend {}

pub struct BaseOTReceiver {
    s: RistrettoBasepointTable,
    counter: u128,
}

pub struct OTSender {
    base: BaseOTSender,
}

pub struct OTReceiver {
    base: BaseOTReceiver,
}

impl OTSender {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let y = Scalar::random(rng);
        Self {
            base: BaseOTSender {
                y,
                s: &y * &RISTRETTO_BASEPOINT_TABLE,
                counter: 0,
            },
        }
    }

    pub fn setup(&self) -> OTSetupSender {
        OTSetupSender { s: self.base.s }
    }

    pub fn encode_base_labels(
        &mut self,
        inputs: &[[Block; 2]],
        points: &[RistrettoPoint],
    ) -> Vec<[Block; 2]> {
        let ys = self.base.y * self.base.s;
        let ks: Vec<[Block; 2]> = inputs
            .iter()
            .zip(points)
            .enumerate()
            .map(|(i, (input, point))| {
                let tweak = (self.base.counter as usize) + i;
                let yr = self.base.y * point;
                let k0 = Block::hash_point(&yr, tweak);
                let k1 = Block::hash_point(&(yr - ys), tweak);
                let c0 = k0 ^ input[0];
                let c1 = k1 ^ input[1];
                [c0, c1]
            })
            .collect();
        self.base.counter += inputs.len() as u128;

        ks
    }
}

impl OTReceiver {
    pub fn new(s_setup: &OTSetupSender) -> Self {
        Self {
            base: BaseOTReceiver {
                s: RistrettoBasepointTable::create(&s_setup.s),
                counter: 0,
            },
        }
    }

    pub fn setup<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        choice: &[bool],
    ) -> Vec<(RistrettoPoint, Block)> {
        let zero = &Scalar::zero() * &self.base.s;
        let one = &Scalar::one() * &self.base.s;
        let ks: Vec<(RistrettoPoint, Block)> = choice
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let tweak = (self.base.counter as usize) + i;
                let x = Scalar::random(rng);
                let c = if *b { one } else { zero };
                let r = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                let k = Block::hash_point(&(&x * &self.base.s), tweak);
                (r, k)
            })
            .collect();
        self.base.counter += choice.len() as u128;
        ks
    }

    pub fn decode_base_labels(
        &self,
        choice: &[bool],
        hs: &[Block],
        encoded_labels: &[[Block; 2]],
    ) -> Vec<Block> {
        choice
            .iter()
            .zip(hs.iter())
            .zip(encoded_labels.iter())
            .map(|((c, h), labels)| *h ^ if *c { labels[1] } else { labels[0] })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_base_ot() {
        let mut s_rng = ChaCha12Rng::from_entropy();
        let mut r_rng = ChaCha12Rng::from_entropy();
        let mut sender = OTSender::new(&mut s_rng);

        let s_setup = sender.setup();
        let s_inputs = [
            [Block::new(0), Block::new(1)],
            [Block::new(2), Block::new(3)],
        ];

        let mut receiver = OTReceiver::new(&s_setup);
        let choice = [false, true];

        let r_setup = receiver.setup(&mut r_rng, &choice);
        let (r_points, r_hs): (Vec<RistrettoPoint>, Vec<Block>) = r_setup.into_iter().unzip();

        let encoded_labels = sender.encode_base_labels(&s_inputs, &r_points.as_slice());

        let received = receiver.decode_base_labels(&choice, &r_hs, &encoded_labels);
        assert_eq!(received, [Block::new(0), Block::new(3)]);
    }
}
