use crate::{bitid::IdSet, encodings::FullEncodings};

#[allow(unused_imports)]
//pub mod backend;
pub mod commitment;
pub mod error;
pub mod state;
pub mod verifier;

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
    fn get_by_ids(&self, ids: T) -> Result<FullEncodings<T>, EncodingProviderError>;
}
