//! This module implements the M2A algorithm.

use super::{a2m::AddShare, OTEnvelope, ShareConvert};
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
    ) -> Result<(AddShare<T>, OTEnvelope<T>), ShareConversionCoreError> {
        // create random masks
        let mut masks: Vec<T> = vec![T::zero(); T::BIT_SIZE as usize];
        masks.iter_mut().for_each(|x| *x = T::rand(rng));

        let t0: Vec<T> = masks.clone();

        // we multiply `self.inner()` with 2^k and add a mask
        let mut t1 = vec![T::zero(); T::BIT_SIZE as usize];
        for (k, t) in t1.iter_mut().enumerate() {
            *t = (self.inner() * T::two_pow(k as u32)) + masks[k]
        }

        // the additive share for the sender is the sum over t0 with a minus sign
        let add_share = AddShare::new(-t0.iter().fold(T::zero(), |acc, i| acc + *i));
        Ok((add_share, OTEnvelope::new(t0, t1)?))
    }
}

impl<T: Field> ShareConvert for MulShare<T> {
    type Inner = T;
    type Output = AddShare<T>;

    fn new(share: Self::Inner) -> Self {
        Self(share)
    }

    #[inline]
    fn inner(&self) -> Self::Inner {
        self.0
    }

    fn convert<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Output, OTEnvelope<T>), ShareConversionCoreError> {
        self.convert_to_additive(rng)
    }
}
