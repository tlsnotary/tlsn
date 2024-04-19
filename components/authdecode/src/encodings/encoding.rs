use crate::SSP;

/// An encoding of either the 0 or the 1 value of a bit.
#[derive(Clone, PartialEq, Debug)]
pub struct Encoding {
    /// The value of the encoding. Byte representation is in big-endian byte order.
    value: [u8; SSP / 8],
    /// The value of the bit that the encoding encodes.
    pub bit: bool,
}

impl Encoding {
    pub fn new(value: [u8; SSP / 8], bit: bool) -> Self {
        Self { value, bit }
    }

    /// Returns the value of the encoding in big-endian byte order.
    pub fn value(&self) -> &[u8; SSP / 8] {
        &self.value
    }
}
