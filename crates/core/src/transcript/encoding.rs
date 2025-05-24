//! Transcript encoding commitments and proofs.
//!
//! This is an internal module that is not intended to be used directly by
//! users.

mod encoder;
mod proof;
mod provider;
mod tree;

pub use encoder::{new_encoder, Encoder, EncoderSecret};
pub use proof::{EncodingProof, EncodingProofError};
pub use provider::{EncodingProvider, EncodingProviderError};
pub use tree::{EncodingTree, EncodingTreeError};

use serde::{Deserialize, Serialize};

use crate::hash::{impl_domain_separator, TypedHash};

/// Transcript encoding commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingCommitment {
    /// Merkle root of the encoding commitments.
    pub root: TypedHash,
    /// Seed used to generate the encodings.
    pub secret: EncoderSecret,
}

impl_domain_separator!(EncodingCommitment);
