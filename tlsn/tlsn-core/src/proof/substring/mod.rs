//! This module supports different types of substring proofs.

use crate::Direction;
use std::fmt::Debug;
use thiserror::Error;
use utils::range::RangeSet;

mod commitment;
mod label;

pub use commitment::{
    CommitmentProof, CommitmentProofBuilder, CommitmentProofBuilderError, CommitmentProofError,
};
pub use label::{LabelProof, LabelProofBuilder, LabelProofBuilderError};

/// A trait that allows to build a substrings proof for a transcript
pub trait SubstringProofBuilder<T>: Debug {
    /// Reveals the given range of bytes in the transcript.
    fn reveal(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut dyn SubstringProofBuilder<T>, SubstringProofBuilderError>;

    /// Builds the proof.
    fn build(self: Box<Self>) -> Result<T, SubstringProofBuilderError>;
}

/// The error type for substring proof builders.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum SubstringProofBuilderError {
    #[error(transparent)]
    Commit(#[from] CommitmentProofBuilderError),
    #[error(transparent)]
    Label(#[from] LabelProofBuilderError),
}
