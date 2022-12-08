//! This module implements the A2M algorithm.

use super::MulShare;
use super::{Gf2_128ShareConvert, OTEnvelope};
use crate::gf2_128::{inverse, mul};
use rand::{CryptoRng, Rng};

/// An additive share of `A = x + y`
#[derive(Clone, Copy, Debug)]
pub struct AddShare(u128);

impl AddShare {
    /// Turn into a multiplicative share and get values for OT
    ///
    /// This function returns
    ///   * `MulShare` - The sender's multiplicative share
    ///   * `OTEnvelope` - Used for oblivious transfer
    pub fn convert_to_multiplicative<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (MulShare, OTEnvelope) {
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

        (mul_share, OTEnvelope(b0.to_vec(), b1.to_vec()))
    }
}

impl Gf2_128ShareConvert for AddShare {
    type Output = MulShare;

    fn new(share: u128) -> Self {
        Self(share)
    }

    #[inline]
    fn inner(&self) -> u128 {
        self.0
    }

    fn convert<R: Rng + CryptoRng>(&self, rng: &mut R) -> (Self::Output, OTEnvelope) {
        self.convert_to_multiplicative(rng)
    }
}
