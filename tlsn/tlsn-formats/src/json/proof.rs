use std::ops::Range;

use spansy::{json::JsonValue, Spanned};
use tlsn_core::{
    commitment::{CommitmentId, CommitmentKind, TranscriptCommitments},
    proof::{SubstringsProofBuilder, SubstringsProofBuilderError},
    Direction,
};

use crate::json::public_ranges;

/// JSON proof builder error.
#[derive(Debug, thiserror::Error)]
pub enum JsonProofBuilderError {
    /// Missing value
    #[error("missing value at path: {0}")]
    MissingValue(String),
    /// Missing commitment.
    #[error("missing commitment")]
    MissingCommitment,
    /// Substrings proof builder error.
    #[error("proof builder error: {0}")]
    Proof(#[from] SubstringsProofBuilderError),
}

/// Builder for proofs of a JSON value.
#[derive(Debug)]
pub struct JsonProofBuilder<'a, 'b> {
    builder: &'a mut SubstringsProofBuilder<'b>,
    commitments: &'a TranscriptCommitments,
    value: &'a JsonValue,
    direction: Direction,
    built: &'a mut bool,
}

impl<'a, 'b> JsonProofBuilder<'a, 'b> {
    pub(crate) fn new(
        builder: &'a mut SubstringsProofBuilder<'b>,
        commitments: &'a TranscriptCommitments,
        value: &'a JsonValue,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        JsonProofBuilder {
            builder,
            commitments,
            value,
            direction,
            built,
        }
    }

    /// Proves the entire JSON value.
    pub fn all(&mut self) -> Result<(), JsonProofBuilderError> {
        let id = self
            .commit_id(self.value.span().range())
            .ok_or(JsonProofBuilderError::MissingCommitment)?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Proves the value at the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the value to prove.
    pub fn path(&mut self, path: &str) -> Result<(), JsonProofBuilderError> {
        let value = self
            .value
            .get(path)
            .ok_or_else(|| JsonProofBuilderError::MissingValue(format!("\"{}\"", path)))?;

        let id = self
            .commit_id(value.span().range())
            .ok_or(JsonProofBuilderError::MissingCommitment)?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Finishes building the JSON proof.
    pub fn build(self) -> Result<(), JsonProofBuilderError> {
        let public_ranges = public_ranges(self.value);

        let public_id = self
            .commitments
            .get_id_by_info(CommitmentKind::Blake3, public_ranges, self.direction)
            .ok_or(JsonProofBuilderError::MissingCommitment)?;

        self.builder.reveal(public_id)?;

        *self.built = true;

        Ok(())
    }

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), self.direction)
    }
}
