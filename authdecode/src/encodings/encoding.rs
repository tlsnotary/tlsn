use super::{state, state::EncodingState};
use crate::SSP;
use mpz_core::utils::blake3;

/// An encoding of either the 0 or the 1 value of a bit.
#[derive(Clone, PartialEq, Debug)]
pub struct Encoding<S: EncodingState = state::Original> {
    /// The value of the encoding. Byte representation is in big-endian byte order.
    value: Vec<u8>,
    /// The value of the bit that the encoding encodes.
    pub bit: bool,
    /// The state of the encoding.
    pub state: S,
}

impl Encoding<state::Original> {
    pub fn new(value: Vec<u8>, bit: bool) -> Self {
        Self {
            value,
            bit,
            state: state::Original {},
        }
    }

    /// Converts the encoding.
    pub fn convert(&self) -> Encoding<state::Converted> {
        let uncorrelated = self.break_correlation();
        uncorrelated.truncate()
    }

    /// Breaks the correlation which this encoding has with its complementary encoding.
    /// Returns an uncorrelated encoding.
    ///
    /// In half-gates garbling scheme, each pair of bit encodings is correlated by a global delta.
    /// It is essential for the security of the AuthDecode protocol that this correlation is removed.   
    ///
    /// # Panics
    ///
    /// Panics it the encoding is not in the `Original` state.
    fn break_correlation(&self) -> Encoding<state::Uncorrelated> {
        // Hashes the encoding if it encodes bit 1 and uses the first 16 bytes of the digest as the
        // new encoding. If it encodes bit 0, keeps the encoding.
        if self.bit {
            let mut new_encoding = [0u8; 16];
            new_encoding.copy_from_slice(&blake3(&self.value)[0..16]);
            Encoding {
                value: new_encoding.to_vec(),
                bit: self.bit,
                state: state::Uncorrelated {},
            }
        } else {
            Encoding {
                value: self.value.clone(),
                bit: self.bit,
                state: state::Uncorrelated {},
            }
        }
    }
}

impl Encoding<state::Uncorrelated> {
    /// Truncates the encoding to SSP most significant bits.
    ///
    /// Note: we assume here that the MSBs are private. This is in line with most garbled circuits
    /// implementations which designate the LSB as a public "pointer" bit.
    ///
    /// Truncation is an optimization. Using encodings of bitlength > SSP is also acceptable.
    fn truncate(self) -> Encoding<state::Converted> {
        Encoding {
            value: self.value[0..SSP / 8].to_vec(),
            bit: self.bit,
            state: state::Converted {},
        }
    }
}

impl<S> Encoding<S>
where
    S: EncodingState,
{
    /// Returns the value of the encoding in big-endian byte order.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
