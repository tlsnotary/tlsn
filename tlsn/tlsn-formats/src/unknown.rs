use std::ops::Range;

use serde::{Deserialize, Serialize};

use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    proof::{ProofBuilder, ProofBuilderError},
    Direction,
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnknownCommitmentBuilderError {
    /// The provided range is out of bounds of the span.
    #[error("provided range is out of bounds of the span")]
    OutOfBounds,
    #[error("commitment builder error: {0}")]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnknownProofBuilderError {
    /// Missing commitment.
    #[error("missing commitment")]
    MissingCommitment,
    /// The provided range is out of bounds of the span.
    #[error("provided range is out of bounds of the span")]
    OutOfBounds,
    /// Substrings proof builder error.
    #[error("proof builder error: {0}")]
    Proof(#[from] ProofBuilderError),
}

/// A span within the transcript with an unknown format.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnknownSpan(pub(crate) Range<usize>);

impl UnknownSpan {
    pub(crate) fn new(span: Range<usize>) -> Self {
        UnknownSpan(span)
    }
}

/// A builder for commitments to spans with an unknown format.
#[derive(Debug)]
pub struct UnknownCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    span: Range<usize>,
    direction: Direction,
    built: &'a mut bool,
}

impl<'a> UnknownCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        span: &'a UnknownSpan,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        UnknownCommitmentBuilder {
            builder,
            span: span.0.clone(),
            direction,
            built,
        }
    }

    /// Commits to the given range within the span.
    pub fn range(
        &mut self,
        range: Range<usize>,
    ) -> Result<CommitmentId, UnknownCommitmentBuilderError> {
        let span_range = self.span.clone();

        let start = span_range.start + range.start;
        let end = span_range.start + range.end;

        if start >= end || end > span_range.end {
            return Err(UnknownCommitmentBuilderError::OutOfBounds);
        }

        match self.direction {
            Direction::Sent => self.builder.commit_sent(start..end),
            Direction::Received => self.builder.commit_recv(start..end),
        }
        .map_err(From::from)
    }

    /// Commits to the entire body.
    pub fn all(&mut self) -> Result<CommitmentId, UnknownCommitmentBuilderError> {
        match self.direction {
            Direction::Sent => self.builder.commit_sent(self.span.clone()),
            Direction::Received => self.builder.commit_recv(self.span.clone()),
        }
        .map_err(From::from)
    }

    /// Builds the commitment.
    pub fn build(self) -> Result<(), UnknownCommitmentBuilderError> {
        // commit to the entire span
        match self.direction {
            Direction::Sent => self.builder.commit_sent(self.span.clone()),
            Direction::Received => self.builder.commit_recv(self.span.clone()),
        }?;

        *self.built = true;

        Ok(())
    }
}

/// A proof builder for spans with an unknown format.
#[derive(Debug)]
pub struct UnknownProofBuilder<'a, T> {
    builder: &'a mut dyn ProofBuilder<T>,
    span: Range<usize>,
    direction: Direction,
    built: &'a mut bool,
}

impl<'a, T> UnknownProofBuilder<'a, T> {
    pub(crate) fn new(
        builder: &'a mut dyn ProofBuilder<T>,
        span: &'a UnknownSpan,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        UnknownProofBuilder {
            builder,
            span: span.0.clone(),
            direction,
            built,
        }
    }

    /// Reveals the entire span.
    pub fn all(&mut self) -> Result<(), UnknownProofBuilderError> {
        self.builder
            .reveal(self.span.clone().into(), self.direction)?;

        Ok(())
    }

    /// Reveals the given range within the span.
    ///
    /// # Arguments
    ///
    /// * `range` - The range to reveal.
    pub fn range(&mut self, range: Range<usize>) -> Result<(), UnknownProofBuilderError> {
        let span_range = self.span.clone();

        let start = span_range.start + range.start;
        let end = span_range.start + range.end;

        if start >= end || end > span_range.end {
            return Err(UnknownProofBuilderError::OutOfBounds);
        }

        self.builder.reveal((start..end).into(), self.direction)?;

        Ok(())
    }

    /// Builds the proof.
    pub fn build(self) -> Result<(), UnknownProofBuilderError> {
        *self.built = true;

        Ok(())
    }
}
