//! This module supports different types of substring proofs.

mod commitment;
mod transcript;

pub use commitment::{
    CommitmentProof, CommitmentProofBuilder, CommitmentProofBuilderError, CommitmentProofError,
};
pub use transcript::{TranscriptProof, TranscriptProofError};
