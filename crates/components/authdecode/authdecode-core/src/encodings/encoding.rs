use crate::SSP;

use getset::Getters;

#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use rand_core::CryptoRng;

/// An encoding of either the 0 or the 1 value of a bit.
#[derive(Clone, PartialEq, Debug, Default, Copy, Getters)]
pub struct Encoding {
    /// The value of the encoding as little-endian bytes.
    #[getset(get = "pub")]
    value: [u8; SSP / 8],
    /// The value of the bit that the encoding encodes.
    #[getset(get = "pub")]
    bit: bool,
}

impl Encoding {
    /// Creates a new instance.
    pub fn new(value: [u8; SSP / 8], bit: bool) -> Self {
        Self { value, bit }
    }

    #[cfg(test)]
    /// Returns a random encoding using the provided RNG.
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen(), rng.gen())
    }

    #[cfg(test)]
    /// Sets the value of the bit that the encoding encodes.
    pub fn set_bit(&mut self, bit: bool) {
        self.bit = bit;
    }
}
