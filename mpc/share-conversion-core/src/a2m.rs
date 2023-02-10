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
        masks.iter_mut().for_each(|x| *x = T::rand(rng));

        // set the last mask such that the sum of all [T::BIT_SIZE] masks equals 0
        masks[T::BIT_SIZE as usize - 1] = -masks
            .iter()
            .take(T::BIT_SIZE as usize - 1)
            .fold(T::zero(), |acc, i| acc + *i);

        // the inverse of the random share will be the multiplicative share for the sender
        let mul_share = MulShare::new(random.inverse());

        // decompose the share into a sum of components, e.g. if the share is 10110, we decompose it into
        // 0 + 10 + 100 + 0000 + 10000
        let components: Vec<T> = (0..T::BIT_SIZE)
            .map(|k| {
                // we extract a bit of `self.inner()` in position `k` (counting from the left) and
                // then left-shift that bit by `k`;
                let mut bits = vec![false; T::BIT_SIZE as usize];
                bits[k as usize] = self.inner().get_bit_msb0(k);
                T::from_bits_msb0(&bits)
            })
            .collect();

        let mut b0 = vec![T::zero(); T::BIT_SIZE as usize];
        for ((b, c), m) in b0.iter_mut().zip(components.iter()).zip(masks.iter()) {
            *b = (*c * random) + *m;
        }

        let mut b1 = vec![T::zero(); T::BIT_SIZE as usize];
        for (k, ((b, c), m)) in b1
            .iter_mut()
            .zip(components.iter())
            .zip(masks.iter())
            .enumerate()
        {
            *b = ((*c + T::two_pow(k as u32)) * random) + *m;
        }

        Ok((mul_share, OTEnvelope::new(b0, b1)?))
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
