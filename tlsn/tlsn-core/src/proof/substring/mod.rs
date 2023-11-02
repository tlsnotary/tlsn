//! This module supports different types of substring proofs.

mod commitment;
mod label;

pub use commitment::{
    CommitmentProof, CommitmentProofBuilder, CommitmentProofBuilderError, CommitmentProofError,
};
pub use label::{LabelProof, LabelProofError};
