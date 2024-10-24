use crate::transcript::{Direction, Idx};

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a subsequence of plaintext.
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>>;

    /// Provides the encoding of each individual bit of a subsequence of plaintext in LSB0 bit order.
    fn provide_bit_encodings(&self, direction: Direction, idx: &Idx) -> Option<Vec<Vec<u8>>>;
}
