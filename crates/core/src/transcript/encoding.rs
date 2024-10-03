//! Transcript encoding commitments and proofs.
//!
//! This is an internal module that is not intended to be used directly by
//! users.

mod encoder;
mod proof;
mod provider;
mod tree;

pub(crate) use encoder::{new_encoder, Encoder};
pub use proof::{EncodingProof, EncodingProofError};
pub use provider::EncodingProvider;
pub use tree::EncodingTree;

use serde::{Deserialize, Serialize};

use crate::hash::{impl_domain_separator, TypedHash};

/// The maximum allowed total bytelength of all committed data. Used to prevent
/// DoS during verification. (this will cause the verifier to hash up to a max
/// of 1GB * 128 = 128GB of plaintext encodings if the commitment type is
/// [crate::commitment::Blake3]).
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 <<
/// 31) - 1 by default)
const MAX_TOTAL_COMMITTED_DATA: usize = 1_000_000_000;

/// Transcript encoding commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingCommitment {
    /// Merkle root of the encoding commitments.
    pub root: TypedHash,
    /// Seed used to generate the encodings.
    pub seed: Vec<u8>,
}

impl_domain_separator!(EncodingCommitment);
