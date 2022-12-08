//! This module implements the M2A algorithm.

use super::a2m::AddShare;
use super::{Gf2_128ShareConvert, OTEnvelope};
use crate::gf2_128::mul;
use rand::{CryptoRng, Rng};

/// A multiplicative share of `A = a * b`
#[derive(Clone, Copy, Debug)]
pub struct MulShare(u128);

impl MulShare {
    /// Turn into an additive share and get values for OT
    ///
    /// This function returns
    ///   * `AddShare` - The sender's additive share
    ///   * `OTEnvelope` - Used for oblivious transfer
    pub fn convert_to_additive<R: Rng + CryptoRng>(&self, rng: &mut R) -> (AddShare, OTEnvelope) {
        let t0: [u128; 128] = std::array::from_fn(|_| rng.gen());
        let t1: [u128; 128] = std::array::from_fn(|i| mul(self.inner(), 1 << i) ^ t0[i]);

        let add_share = AddShare::new(t0.into_iter().fold(0, |acc, i| acc ^ i));
        (add_share, OTEnvelope(t0.to_vec(), t1.to_vec()))
    }
}

impl Gf2_128ShareConvert for MulShare {
    type Output = AddShare;

    fn new(share: u128) -> Self {
        Self(share)
    }

    #[inline]
    fn inner(&self) -> u128 {
        self.0
    }

    fn convert<R: Rng + CryptoRng>(&self, rng: &mut R) -> (Self::Output, OTEnvelope) {
        self.convert_to_additive(rng)
    }
}
