//! This module implements the M2A algorithm.

use super::{a2m::AddShare, Gf2_128ShareConvert, OTEnvelope};
use crate::{gf2_128::mul, ShareConversionCoreError};
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
    pub fn convert_to_additive<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(AddShare, OTEnvelope), ShareConversionCoreError> {
        let masks: [u128; 128] = std::array::from_fn(|_| rng.gen());

        let t0: [u128; 128] = std::array::from_fn(|i| masks[i]);
        let t1: [u128; 128] = std::array::from_fn(|i| mul(self.inner(), 1 << i) ^ masks[i]);

        let add_share = AddShare::new(t0.into_iter().fold(0, |acc, i| acc ^ i));
        Ok((add_share, OTEnvelope::new(t0.to_vec(), t1.to_vec())?))
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

    fn convert<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Output, OTEnvelope), ShareConversionCoreError> {
        self.convert_to_additive(rng)
    }
}
