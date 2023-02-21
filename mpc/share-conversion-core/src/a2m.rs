//! This module implements the A2M algorithm.

use super::{MulShare, OTEnvelope, ShareConvert};
use crate::{fields::Field, ShareConversionCoreError};
use rand::{CryptoRng, Rng};

/// An additive share of `A = x + y`
#[derive(Clone, Copy, Debug)]
pub struct AddShare<T>(T);

impl<T: Field> AddShare<T> {
    /// Turn into a multiplicative share and get values for OT
    ///
    /// This function returns
    ///   * `MulShare` - The sender's multiplicative share
    ///   * `OTEnvelope` - Used for oblivious transfer
    pub fn convert_to_multiplicative<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MulShare<T>, OTEnvelope<T>), ShareConversionCoreError> {
        // We need to exclude 0 here, because it does not have an inverse
        // which is needed later
        let random: T = loop {
            let r = T::rand(rng);
            if r != T::zero() {
                break r;
            }
        };
        let mut masks: Vec<T> = vec![T::zero(); T::BIT_SIZE as usize];
        masks.iter_mut().for_each(|m| *m = T::rand(rng));

        // set the last mask such that the sum of all [T::BIT_SIZE] masks equals 0
        masks[T::BIT_SIZE as usize - 1] = -masks
            .iter()
            .take(T::BIT_SIZE as usize - 1)
            .fold(T::zero(), |acc, i| acc + *i);

        // the inverse of the random share will be the multiplicative share for the sender
        let mul_share = MulShare::new(random.inverse());

        // Each choice bit of the peer's share `y` represents a summand of `y`, e.g.
        // if `y` is 10110 (in binary), then the choice bits (0,1,1,0,1) represent the summands
        // (0, 10, 100, 0000, 10000).
        // For each peer's summand, we send back `summand * random` with a mask to hide the product.

        let values: Vec<[T; 2]> = (0..T::BIT_SIZE)
            .map(|k| {
                // when summand is zero, we just send the mask
                let mut v0 = masks[k as usize];

                // otherwise we send `summand * random + mask`
                let mut bits = vec![false; T::BIT_SIZE as usize];
                bits[(T::BIT_SIZE - 1 - k) as usize] = true;
                let summand = T::from_bits_msb0(&bits);
                let mut v1 = (summand * random) + masks[k as usize];

                // add `x * random` to the last value, so that when the peer sums up all values,
                // he will get `(y + x) * random`, which will be his multiplicative share
                if k == T::BIT_SIZE - 1 {
                    v0 = v0 + self.inner() * random;
                    v1 = v1 + self.inner() * random;
                }
                [v0, v1]
            })
            .collect();

        let (v0, v1): (Vec<T>, Vec<T>) = values.into_iter().map(|[v0, v1]| (v0, v1)).unzip();

        Ok((mul_share, OTEnvelope::new(v0, v1)?))
    }
}

impl<T: Field> ShareConvert for AddShare<T> {
    type Inner = T;
    type Output = MulShare<T>;

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
        self.convert_to_multiplicative(rng)
    }
}
