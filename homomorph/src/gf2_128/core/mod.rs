//! This module implements the core logic, i.e. no input/output.

mod a2m;
mod m2a;

/// A trait for converting field elements
///
/// Allows 2 parties to switch between additively and multiplicatively
/// shared representations of a field element.
pub trait Gf2_128HomomorphicConvert
where
    Self: Sized,
{
    type Output: Gf2_128HomomorphicConvert;

    /// Create a new instance
    fn new(share: u128) -> Self;

    /// Return the inner value
    fn inner(&self) -> u128;

    /// Create a share of type `Self` from the result of an oblivious transfer (OT)
    ///
    /// The `value` needs to be built by choices of an OT
    fn from_choice(value: &[u128]) -> Self {
        Self::new(value.iter().fold(0, |acc, i| acc ^ i))
    }

    /// Prepares a share for conversion in an OT
    ///
    /// Converts the share to a new share and returns, what is needed for sending in an OT.
    fn convert(&self) -> (Self::Output, MaskedPartialValue);
}

/// Masked values for an oblivious transfer
#[derive(Clone, Debug)]
pub struct MaskedPartialValue(pub(crate) Vec<u128>, pub(crate) Vec<u128>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf2_128::mul;
    use a2m::AddShare;
    use m2a::MulShare;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn ot_mock(envelopes: MaskedPartialValue, choices: u128) -> Vec<u128> {
        let mut out: Vec<u128> = vec![0; 128];
        for (k, number) in out.iter_mut().enumerate() {
            let bit = (choices >> k) & 1;
            *number = (bit * envelopes.1[k]) ^ ((bit ^ 1) * envelopes.0[k]);
        }
        out
    }

    #[test]
    fn test_m2a() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: MulShare = MulShare::new(rng.gen());
        let b: MulShare = MulShare::new(rng.gen());

        let (x, sharings) = a.to_additive();

        let choice = ot_mock(sharings, b.inner());
        let y = AddShare::from_choice(&choice);

        assert_eq!(mul(a.inner(), b.inner()), x.inner() ^ y.inner());
    }

    #[test]
    fn test_a2m() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let x: AddShare = AddShare::new(rng.gen());
        let y: AddShare = AddShare::new(rng.gen());

        let (a, sharings) = x.to_multiplicative();

        let choice = ot_mock(sharings, y.inner());
        let b = MulShare::from_choice(&choice);

        assert_eq!(x.inner() ^ y.inner(), mul(a.inner(), b.inner()));
    }
}
