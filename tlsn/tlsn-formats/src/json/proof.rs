use spansy::{json::JsonValue, Spanned};
use tlsn_core::{
    proof::{ProofBuilder, ProofBuilderError},
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
    Proof(#[from] ProofBuilderError),
}

/// Builder for proofs of a JSON value.
#[derive(Debug)]
pub struct JsonProofBuilder<'a, T> {
    builder: &'a mut dyn ProofBuilder<T>,
    value: &'a JsonValue,
    direction: Direction,
    built: &'a mut bool,
}

impl<'a, T> JsonProofBuilder<'a, T> {
    pub(crate) fn new(
        builder: &'a mut dyn ProofBuilder<T>,
        value: &'a JsonValue,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        JsonProofBuilder {
            builder,
            value,
            direction,
            built,
        }
    }

    /// Proves the entire JSON value.
    pub fn all(&mut self) -> Result<(), JsonProofBuilderError> {
        self.builder
            .reveal(self.value.span().range().into(), self.direction)?;

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

        self.builder
            .reveal(value.span().range().into(), self.direction)?;

        Ok(())
    }

    /// Finishes building the JSON proof.
    pub fn build(self) -> Result<(), JsonProofBuilderError> {
        let public_ranges = public_ranges(self.value);
        self.builder.reveal(public_ranges, self.direction)?;

        *self.built = true;
        Ok(())
    }
}
