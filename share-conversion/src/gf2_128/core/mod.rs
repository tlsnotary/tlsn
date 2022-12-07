//! This module implements the core logic, i.e. no IO

mod a2m;
mod m2a;

pub(crate) use a2m::AddShare;
pub(crate) use m2a::MulShare;
use mpc_core::Block;

/// A trait for converting field elements
///
/// Allows two parties to switch between additively and multiplicatively
/// shared representations of a field element.
pub trait Gf2_128ShareConvert: Copy
where
    Self: Sized,
{
    type Output: Gf2_128ShareConvert;

    /// Create a new instance
    fn new(share: u128) -> Self;

    /// Converts '&self' into choices needed for the receiver input to an oblivious transfer
    fn choices(&self) -> Vec<bool> {
        let mut out: Vec<bool> = Vec::with_capacity(128);
        for k in 0..128 {
            out.push((self.inner() >> k & 1) == 1);
        }
        out
    }

    /// Return the inner value
    fn inner(&self) -> u128;

    /// Create a share of type `Self::Output` from the result of an oblivious transfer (OT)
    ///
    /// The `value` needs to be built from the output of an OT
    fn from_choice(value: &[u128]) -> Self::Output {
        Self::Output::new(value.iter().fold(0, |acc, i| acc ^ i))
    }

    /// Prepares a share for conversion in an OT
    ///
    /// Converts the share to a new share and returns, what is needed for sending in an OT.
    fn convert(&self) -> (Self::Output, OTEnvelope);
}

/// Batched values for several oblivious transfers
///
/// The inner tuples `.0` and `.1` belong to the corresponding receiver's choice bit
#[derive(Clone, Debug)]
pub struct OTEnvelope(pub(crate) Vec<u128>, pub(crate) Vec<u128>);

impl OTEnvelope {
    /// Allows to aggregate envelopes
    pub(crate) fn extend(&mut self, other: OTEnvelope) {
        self.0.extend_from_slice(&other.0);
        self.1.extend_from_slice(&other.1);
    }
}

impl From<OTEnvelope> for Vec<[Block; 2]> {
    fn from(value: OTEnvelope) -> Self {
        let mut out = Vec::with_capacity(value.0.len());
        for (zero, one) in value.0.iter().zip(value.1.iter()) {
            out.push([Block::new(*zero), Block::new(*one)])
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

        let (x, sharings) = a.convert_to_additive();

        let choice = mock_ot(sharings, b.inner());
        let y = AddShare::from_choice(&choice);

        assert_eq!(mul(a.inner(), b.inner()), x.inner() ^ y.inner());
    }

    #[test]
    fn test_a2m() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let x: AddShare = AddShare::new(rng.gen());
        let y: AddShare = AddShare::new(rng.gen());

        let (a, sharings) = x.convert_to_multiplicative();

        let choice = mock_ot(sharings, y.inner());
        let b = MulShare::from_choice(&choice);

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
