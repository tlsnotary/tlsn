//! This module implements the A2M algorithm.

use super::m2a::MulShare;
use super::{Gf2_128HomomorphicConvert, MaskedPartialValue};
use crate::gf2_128::{inverse, mul};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// An additive share of `A = x + y`
#[derive(Clone, Copy, Debug)]
pub struct AddShare(u128);

impl AddShare {
    /// Turn into a multiplicative share and masked partial values
    ///
    /// This function returns
    ///   * `MulShare` - The sender's multiplicative share
    ///   * `MaskedPartialValue` - Used for oblivious transfer
    pub fn to_multiplicative(&self) -> (MulShare, MaskedPartialValue) {
        let mut rng = ChaCha12Rng::from_entropy();

        let random: u128 = rng.gen();
        if random == 0 {
            panic!("Random u128 is 0");
        }

        let mut masks: [u128; 128] = std::array::from_fn(|_| rng.gen());
        // set the last mask such that the sum of all 128 masks equals 0
        masks[127] = masks.into_iter().take(127).fold(0, |acc, i| acc ^ i);

        let mul_share = MulShare::new(inverse(random));

        // `self.inner() & (1 << i)` extracts bit of `self.inner()` in position `i` (counting from
        // the right) shifted left by `i`
        let b0: [u128; 128] =
            std::array::from_fn(|i| mul(self.inner() & (1 << i), random) ^ masks[i]);
        let b1: [u128; 128] =
            std::array::from_fn(|i| mul((self.inner() & (1 << i)) ^ (1 << i), random) ^ masks[i]);

        (mul_share, MaskedPartialValue(b0.to_vec(), b1.to_vec()))
    }
}

impl Gf2_128HomomorphicConvert for AddShare {
    type Output = MulShare;

    fn new(share: u128) -> Self {
        Self(share)
    }

    fn inner(&self) -> u128 {
        self.0
    }

    fn convert(&self) -> (Self::Output, MaskedPartialValue) {
        self.to_multiplicative()
    }
}
