use std::ops::Range;

use utils::range::RangeSet;

use crate::Direction;

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a range of plaintext.
    fn provide_range(&self, range: Range<usize>, direction: Direction) -> Option<Vec<u8>>;

    /// Provides the encoding of a set of ranges of plaintext.
    fn provide_ranges(&self, ranges: RangeSet<usize>, direction: Direction) -> Option<Vec<u8>>;
}
