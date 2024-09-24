use crate::transcript::{Direction, Idx};

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a subsequence of plaintext.
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>>;
}
