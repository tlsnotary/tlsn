//! Transcript encoding commitments and proofs.

mod encoder;
mod proof;
mod proof_builder;
mod provider;
mod tree;
mod tree_builder;

pub(crate) use encoder::{new_encoder, Encoder};
pub use proof::EncodingProof;
pub use proof_builder::EncodingProofBuilder;
pub use provider::EncodingProvider;
pub(crate) use tree::EncodingLeaf;
pub use tree::EncodingTree;
pub use tree_builder::EncodingTreeBuilder;

use serde::{Deserialize, Serialize};

use crate::{hash::Hash, serialize::CanonicalSerialize};

/// The maximum allowed total bytelength of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of plaintext encodings if the
/// commitment type is [crate::commitment::Blake3]).
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 << 31) - 1 by default)
const MAX_TOTAL_COMMITTED_DATA: usize = 1_000_000_000;

/// Transcript encoding commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingCommitment {
    /// The merkle root of the encoding commitments.
    pub root: Hash,
    /// The seed used to generate the encodings.
    pub seed: Vec<u8>,
}

impl CanonicalSerialize for EncodingCommitment {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CanonicalSerialize::serialize(&self.root));
        bytes.extend_from_slice(&self.seed);
        bytes
    }
}
