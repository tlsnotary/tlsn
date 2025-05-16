use std::ops::Range;

use crate::transcript::Direction;

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Writes the encoding of the given range into the destination buffer.
    fn provide_encoding(
        &self,
        direction: Direction,
        range: Range<usize>,
        dest: &mut Vec<u8>,
    ) -> Result<(), EncodingProviderError>;
}

#[derive(Debug, thiserror::Error)]
#[error("failed to provide encoding")]
pub struct EncodingProviderError;
