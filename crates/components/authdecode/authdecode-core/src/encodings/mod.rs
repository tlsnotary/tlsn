pub(crate) mod active;
mod encoding;
mod full;

pub use active::ActiveEncodings;
pub use encoding::Encoding;
pub use full::FullEncodings;

use crate::id::IdCollection;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingProviderError {
    #[error("Unable to provide an encoding with the given id {0}")]
    EncodingWithIdNotAvailable(usize),
}

/// A provider of full encodings of bits identified by their id.
pub trait EncodingProvider<I>
where
    I: IdCollection,
{
    /// Returns full encodings for the given bit ids.
    fn get_by_ids(&self, ids: &I) -> Result<FullEncodings<I>, EncodingProviderError>;
}
