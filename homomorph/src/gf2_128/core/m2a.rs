//! This module implements the M2A algorithm.

use super::a2m::AddShare;
use super::{Gf2_128HomomorphicConvert, MaskedPartialValue};
use crate::gf2_128::mul;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// A multiplicative share of `A = a * b`
#[derive(Clone, Copy, Debug)]
pub struct MulShare(u128);

impl MulShare {
    /// Turn into an additive share and masked partial values
    ///
    /// This function returns
    ///   * `AddShare` - The sender's additive share; this is `y` in the paper
    ///   * `MaskedPartialValue` - Used for oblivious transfer; t0 and t1 in the paper
    pub fn to_additive(&self) -> (AddShare, MaskedPartialValue) {
        let mut rng = ChaCha12Rng::from_entropy();

        let t0: [u128; 128] = std::array::from_fn(|_| rng.gen());
        let t1: [u128; 128] = std::array::from_fn(|i| mul(self.inner(), 1 << i) ^ t0[i]);

        let add_share = AddShare::new(t0.into_iter().fold(0, |acc, i| acc ^ i));
        (add_share, MaskedPartialValue(t0.to_vec(), t1.to_vec()))
    }
}

impl Gf2_128HomomorphicConvert for MulShare {
    type Output = AddShare;

    fn new(share: u128) -> Self {
        Self(share)
    }

    fn inner(&self) -> u128 {
        self.0
    }

    fn convert(&self) -> (Self::Output, MaskedPartialValue) {
        self.to_additive()
    }
}
