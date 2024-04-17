pub mod active;
pub mod encoding;
pub mod full;
pub mod state;

pub use active::ActiveEncodings;
pub use encoding::Encoding;
pub use full::FullEncodings;

use crate::bitid::IdSet;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingProviderError {
    #[error("Unable to provide an encoding with the given id")]
    EncodingWithIdNotAvailable,
}

pub trait EncodingProvider<T>
where
    T: IdSet,
{
    /// Returns full encodings for the given plaintext bit ids.
    fn get_by_ids(&self, ids: &T) -> Result<FullEncodings<T>, EncodingProviderError>;
}
