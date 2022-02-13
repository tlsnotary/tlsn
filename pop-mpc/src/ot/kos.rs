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
    s: RistrettoPoint
}

pub struct OTSend {

}

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
        OTSetupSender {
            s: self.base.s
        }
    }

    // pub fn send(&self, inputs: &[[Block; 2]], points: &[Block]) -> OTSend {
    //     let ys=  self.base.y * self.base.s;
    //     let ks = inputs.iter().zip(points).map(|input, point| {
    //         let yr = self.base.y * point;
    //     }).collect::<[Block; 2]>();

    //     OTSend {}
    // }
}

impl OTReceiver {}
