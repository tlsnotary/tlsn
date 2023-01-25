//! This module implements the M2A and A2M conversion algorithms using oblivious transfer.
//!
//! * M2A: Implementation of chapter 4.1 in <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>
//! * A2M: Adaptation of chapter 4 in <https://www.cs.umd.edu/~fenghao/paper/modexp.pdf>

mod a2m;
mod m2a;

//pub use a2m::AddShare;
pub use m2a::MulShare;
use mpc_core::Block;
use rand::{CryptoRng, Rng};

use crate::{fields::Field, ShareConversionCoreError};

/// A trait for converting field elements
///
/// Allows two parties to switch between additively and multiplicatively
/// shared representations of a field element.
pub trait Gf2_128ShareConvert: Copy
where
    Self: Sized,
{
    type Inner: Field;
    type Output: Gf2_128ShareConvert<Inner = Self::Inner>;

    /// Create a new instance
    fn new(share: Self::Inner) -> Self;

    /// Converts '&self' into choices needed for the receiver input to an oblivious transfer.
    /// The choices are in the "least-bit-first" order.
    fn choices(&self) -> Vec<bool> {
        let len: usize = Self::Inner::BIT_SIZE as usize;
        let mut out: Vec<bool> = Vec::with_capacity(len);
        for k in 0..len {
            out.push(self.inner().get_bit(k));
        }
        out
    }

    /// Return the inner value
    fn inner(&self) -> Self::Inner;

    /// Create a share of type `Self::Output` from the result of an oblivious transfer (OT)
    ///
    /// The `values` needs to be built from the output of an OT
    fn from_sender_values(values: &[Self::Inner]) -> Self::Output {
        Self::Output::new(values.iter().fold(Self::Inner::zero(), |acc, i| acc + *i))
    }

    /// Prepares a share for conversion in an OT
    ///
    /// Converts the share to a new share and returns what is needed for sending in an OT.
    fn convert<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Output, OTEnvelope<Self::Inner>), ShareConversionCoreError>;
}

/// Batched values for several oblivious transfers
///
/// The inner vectors `.0` and `.1` belong to the corresponding receiver's choice bit
#[derive(Clone, Debug, Default)]
pub struct OTEnvelope<T>(Vec<T>, Vec<T>);

impl<T: Field> OTEnvelope<T> {
    /// Create a new `OTEnvelope`
    ///
    /// Checks that both choice vecs have equal length
    pub fn new(zero: Vec<T>, one: Vec<T>) -> Result<Self, ShareConversionCoreError> {
        if zero.len() != one.len() {
            return Err(ShareConversionCoreError::OTEnvelopeUnequalLength);
        }
        Ok(Self(zero, one))
    }

    /// Returns a slice for the `zero` choices
    pub fn zero_choices(&self) -> &[T] {
        &self.0
    }

    /// Returns a slice for the `one` choices
    pub fn one_choices(&self) -> &[T] {
        &self.1
    }

    /// Allows to aggregate envelopes
    pub fn extend(&mut self, other: OTEnvelope<T>) {
        self.0.extend_from_slice(&other.0);
        self.1.extend_from_slice(&other.1);
    }

    /// Get the number of OTs in this envelope
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if envelope is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> From<OTEnvelope<T>> for Vec<[Block; 2]>
where
    T: Field,
    u128: From<T>,
{
    fn from(value: OTEnvelope<T>) -> Self {
        let mut out = Vec::with_capacity(value.0.len());
        for (zero, one) in value.0.iter().zip(value.1.iter()) {
            out.push([Block::new(u128::from(*zero)), Block::new(u128::from(*one))])
        }
        out
    }
}

impl<T> From<OTEnvelope<T>> for Vec<[Vec<u8>; 2]>
where
    T: Field,
    Vec<u8>: From<T>,
{
    fn from(value: OTEnvelope<T>) -> Self {
        let mut out = Vec::with_capacity(value.0.len());
        for (zero, one) in value.0.iter().zip(value.1.iter()) {
            out.push([Vec::<u8>::from(*zero), Vec::<u8>::from(*one)])
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf2_128::mul;
    use a2m::AddShare;
    use m2a::MulShare;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_m2a() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: MulShare = MulShare::new(rng.gen());
        let b: MulShare = MulShare::new(rng.gen());

        let (x, sharings) = a.convert_to_additive(&mut rng).unwrap();

        let choice = mock_ot(sharings, b.inner());
        let y = AddShare::from_sender_values(&choice);

        assert_eq!(mul(a.inner(), b.inner()), x.inner() ^ y.inner());
    }

    #[test]
    fn test_a2m() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let x: AddShare = AddShare::new(rng.gen());
        let y: AddShare = AddShare::new(rng.gen());

        let (a, sharings) = x.convert_to_multiplicative(&mut rng).unwrap();

        let choice = mock_ot(sharings, y.inner());
        let b = MulShare::from_sender_values(&choice);

        assert_eq!(x.inner() ^ y.inner(), mul(a.inner(), b.inner()));
    }

    fn mock_ot(envelopes: OTEnvelope, choices: u128) -> Vec<u128> {
        let mut out: Vec<u128> = vec![0; 128];
        for (k, number) in out.iter_mut().enumerate() {
            let bit = (choices >> k) & 1;
            *number = (bit * envelopes.1[k]) ^ ((bit ^ 1) * envelopes.0[k]);
        }
        out
    }
}
