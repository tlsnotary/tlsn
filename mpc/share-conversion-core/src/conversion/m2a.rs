//! This module implements the M2A algorithm.

use super::{a2m::AddShare, Gf2_128ShareConvert, OTEnvelope};
use crate::{fields::Field, ShareConversionCoreError};
use rand::{CryptoRng, Rng};

/// A multiplicative share of `A = a * b`
#[derive(Clone, Copy, Debug)]
pub struct MulShare<T>(T);

impl<T: Field> MulShare<T> {
    /// Turn into an additive share and get values for OT
    ///
    /// This function returns
    ///   * `AddShare` - The sender's additive share
    ///   * `OTEnvelope` - Used for oblivious transfer
    pub fn convert_to_additive<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(AddShare, OTEnvelope<T>), ShareConversionCoreError> {
        let mut masks: Vec<T> = vec![T::zero(), T::BIT_SIZE];
        rng.fill(&mut masks);

        let t0: Vec<T> = masks.clone();

        let mut t1 = vec![T::zero(), T::BIT_SIZE];
        for (k, el) in t1.iter_mut().enumerate() {
            *el = (*el * (T::one() << k)) ^ masks[k]
        }

        let add_share = AddShare::new(-t0.into_iter().fold(T::zero(), |acc, i| acc + i));
        Ok((add_share, OTEnvelope::new(t0, t1)?))
    }
}

impl<T: Field> Gf2_128ShareConvert for MulShare<T> {
    type Inner = T;
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
    ) -> Result<(Self::Output, OTEnvelope<T>), ShareConversionCoreError> {
        self.convert_to_additive(rng)
    }
}
