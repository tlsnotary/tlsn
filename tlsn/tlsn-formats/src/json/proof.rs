use std::ops::Range;

use spansy::{json::JsonValue, Spanned};
use tlsn_core::{
    commitment::{CommitmentId, CommitmentKind, TranscriptCommitments},
    proof::{SubstringsProofBuilder, SubstringsProofBuilderError},
    Direction,
};

#[derive(Debug, thiserror::Error)]
pub enum JsonProofBuilderError {
    /// Missing value
    #[error("missing value at path: {0}")]
    MissingValue(String),
    /// Missing commitment.
    #[error("missing commitment")]
    MissingCommitment,
    #[error("proof builder error: {0}")]
    Proof(#[from] SubstringsProofBuilderError),
}

#[derive(Debug)]
pub struct JsonProofBuilder<'a> {
    builder: &'a mut SubstringsProofBuilder<'a>,
    commitments: &'a TranscriptCommitments,
    value: &'a JsonValue,
    direction: Direction,
}

impl<'a> JsonProofBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut SubstringsProofBuilder<'a>,
        commitments: &'a TranscriptCommitments,
        value: &'a JsonValue,
        direction: Direction,
    ) -> Self {
        JsonProofBuilder {
            builder,
            commitments,
            value,
            direction,
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

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), self.direction)
    }
}
