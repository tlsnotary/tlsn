use spansy::{
    json::{JsonValue, JsonVisit},
    Spanned,
};
use tlsn_core::{
    commitment::{
        CommitmentId, CommitmentKind, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError,
    },
    Direction,
};

use super::public_ranges;

/// JSON commitment builder error.
#[derive(Debug, thiserror::Error)]
pub enum JsonCommitmentBuilderError {
    /// Invalid path.
    #[error("invalid path: {0}")]
    InvalidPath(String),
    /// Transcript commitment builder error.
    #[error("commitment builder error: {0}")]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

/// Builder for commitments to a JSON value.
#[derive(Debug)]
pub struct JsonCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    value: &'a JsonValue,
    direction: Direction,
    built: &'a mut bool,
}

impl<'a> JsonCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        value: &'a JsonValue,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        JsonCommitmentBuilder {
            builder,
            value,
            direction,
            built,
        }
    }

    /// Commits to the entire JSON value.
    pub fn all(&mut self) -> Result<CommitmentId, JsonCommitmentBuilderError> {
        match self.direction {
            Direction::Sent => self.builder.commit_sent(self.value.span().range()),
            Direction::Received => self.builder.commit_recv(self.value.span().range()),
        }
        .map_err(From::from)
    }

    /// Commits to the value at the given path.
    pub fn path(&mut self, path: &str) -> Result<CommitmentId, JsonCommitmentBuilderError> {
        let value = self.value.get(path).ok_or_else(|| {
            JsonCommitmentBuilderError::InvalidPath(format!("invalid path: {}", path))
        })?;

        let range = value.span().range();
        match self.direction {
            Direction::Sent => self.builder.commit_sent(range),
            Direction::Received => self.builder.commit_recv(range),
        }
        .map_err(From::from)
    }

    /// Finishes building commitments the a JSON value.
    pub fn build(self) -> Result<(), JsonCommitmentBuilderError> {
        let public_ranges = public_ranges(self.value);

        match self.direction {
            Direction::Sent => self.builder.commit_sent(public_ranges)?,
            Direction::Received => self.builder.commit_recv(public_ranges)?,
        };

        let mut visitor = JsonCommitter {
            builder: self.builder,
            direction: self.direction,
            err: None,
        };

        visitor.visit_value(self.value);

        if let Some(err) = visitor.err {
            err?
        }

        *self.built = true;

        Ok(())
    }
}

struct JsonCommitter<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    direction: Direction,
    err: Option<Result<(), JsonCommitmentBuilderError>>,
}

impl<'a> JsonVisit for JsonCommitter<'a> {
    fn visit_number(&mut self, node: &spansy::json::Number) {
        if self.err.is_some() {
            return;
        }

        let range = node.span().range();
        if self
            .builder
            .get_id(CommitmentKind::Blake3, range.clone(), self.direction)
            .is_some()
        {
            return;
        }

        let res = match self.direction {
            Direction::Sent => self.builder.commit_sent(range),
            Direction::Received => self.builder.commit_recv(range),
        }
        .map(|_| ())
        .map_err(From::from);

        if res.is_err() {
            self.err = Some(res);
        }
    }

    fn visit_string(&mut self, node: &spansy::json::String) {
        if self.err.is_some() {
            return;
        }

        // Ignore empty strings.
        let span = node.span();
        if span.is_empty() {
            return;
        }

        let range = span.range();
        if self
            .builder
            .get_id(CommitmentKind::Blake3, range.clone(), self.direction)
            .is_some()
        {
            return;
        }

        let res = match self.direction {
            Direction::Sent => self.builder.commit_sent(range),
            Direction::Received => self.builder.commit_recv(range),
        }
        .map(|_| ())
        .map_err(From::from);

        if res.is_err() {
            self.err = Some(res);
        }
    }
}
