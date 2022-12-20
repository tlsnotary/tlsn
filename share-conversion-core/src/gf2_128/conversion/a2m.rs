//! This module implements the A2M algorithm.

use std::num::NonZeroU128;

use super::{Gf2_128ShareConvert, MulShare, OTEnvelope};
use crate::{
    gf2_128::{inverse, mul},
    ShareConversionCoreError,
};
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
    ) -> Result<(MulShare, OTEnvelope), ShareConversionCoreError> {
        // We need to exclude 0 here, because it does not have an inverse
        // which is needed later
        let random: NonZeroU128 = rng.gen();
        let random = random.get();

        let mut masks: [u128; 128] = std::array::from_fn(|_| rng.gen());
        // set the last mask such that the sum of all 128 masks equals 0
        masks[127] = masks.into_iter().take(127).fold(0, |acc, i| acc ^ i);

        let mul_share = MulShare::new(inverse(random));

        // decompose the share into a sum of components, e.g. if the share is 10110, we decompose it into
        // 0 + 10 + 100 + 0000 + 10000
        let components: Vec<u128> = (0..128)
            .map(|i| {
                // `self.inner() & (1 << i)` first extracts a bit of `self.inner()` in position `i` (counting from
                // the right) and then left-shifts that bit by `i`
                self.inner() & (1 << i)
            })
            .collect();

        let b0: [u128; 128] = std::array::from_fn(|i| mul(components[i], random) ^ masks[i]);
        let b1: [u128; 128] =
            std::array::from_fn(|i| mul(components[i] ^ (1 << i), random) ^ masks[i]);

        Ok((mul_share, OTEnvelope::new(b0.to_vec(), b1.to_vec())?))
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

    fn convert<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Output, OTEnvelope), ShareConversionCoreError> {
        self.convert_to_multiplicative(rng)
    }
}
