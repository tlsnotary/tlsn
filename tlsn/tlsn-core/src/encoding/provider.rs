use crate::transcript::{SliceIdx, SubsequenceIdx};

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a slice of plaintext.
    fn provide_slice(&self, idx: &SliceIdx) -> Option<Vec<u8>>;

    /// Provides the encoding of a subsequence of plaintext.
    fn provide_subsequence(&self, idx: &SubsequenceIdx) -> Option<Vec<u8>>;
}
