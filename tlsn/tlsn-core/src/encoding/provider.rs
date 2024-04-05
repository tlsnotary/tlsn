use crate::transcript::SubsequenceIdx;

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a subsequence of plaintext.
    fn provide_subsequence(&self, idx: &SubsequenceIdx) -> Option<Vec<u8>>;
}
