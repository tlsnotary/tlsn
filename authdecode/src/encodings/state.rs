/// Marker trait for encoding state.
pub trait EncodingState: Clone {}

/// The original unmodified state.
#[derive(Clone, PartialEq, Default)]
pub struct Original {}

/// The state where the correlation (if any) between this encoding and its complementary encoding
/// was removed.
#[derive(Clone, PartialEq, Default)]
pub struct Uncorrelated {}

/// The state after the encoding was made uncorrelated and truncated.
#[derive(Clone, PartialEq, Default)]
pub struct Converted {}
impl EncodingState for Original {}
impl EncodingState for Uncorrelated {}
impl EncodingState for Converted {}
