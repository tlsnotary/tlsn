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

        // generate random masks
        let mut masks: Vec<T> = (0..T::BIT_SIZE as usize).map(|_| T::rand(rng)).collect();

        // set the last mask such that the sum of all [T::BIT_SIZE] masks equals 0
        masks[T::BIT_SIZE as usize - 1] = -masks
            .iter()
            .take(T::BIT_SIZE as usize - 1)
            .fold(T::zero(), |acc, i| acc + *i);

        // split up our additive share `x` into random summands
        let mut x_summands: Vec<T> = (0..T::BIT_SIZE as usize).map(|_| T::rand(rng)).collect();

        // set the last summand such that the sum of all [T::BIT_SIZE] summands equals `x`
        x_summands[T::BIT_SIZE as usize - 1] = self.inner()
            + -x_summands
                .iter()
                .take(T::BIT_SIZE as usize - 1)
                .fold(T::zero(), |acc, i| acc + *i);

        // the inverse of the random share will be the multiplicative share for the sender
        let mul_share = MulShare::new(random.inverse());

        // Each choice bit of the peer's share `y` represents a summand of `y`, e.g.
        // if `y` is 10110 (in binary), then the choice bits in lsb0 order (0,1,1,0,1) represent the
        // summands (0, 10, 100, 0000, 10000).
        // For each peer's summand (called `y_summand`), we send back `(x_summand + y_summand) * random
        // + mask`. The purpose of the mask is to hide the product.

        let (v0, v1): (Vec<T>, Vec<T>) = (0..T::BIT_SIZE)
            .map(|k| {
                // when y_summand is zero, we send `x_summand * random + mask`
                let v0 = x_summands[k as usize] * random + masks[k as usize];

                // otherwise we send `(x_summand + y_summand) * random + mask`
                let mut bits = vec![false; T::BIT_SIZE as usize];
                bits[(T::BIT_SIZE - 1 - k) as usize] = true;
                let y_summand = T::from_bits_msb0(&bits);
                let v1 = (x_summands[k as usize] + y_summand) * random + masks[k as usize];

                (v0, v1)
            })
            .unzip();

        // when the peer adds up all the received values, the masks will cancel one another out and
        // the remaining `(x + y) * random` will be the peer's multiplicative share

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
