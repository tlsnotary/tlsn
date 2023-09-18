use spansy::{json::JsonValue, Spanned};
use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    Direction,
};

#[derive(Debug, thiserror::Error)]
pub enum JsonCommitmentBuilderError {
    #[error("commitment builder error: {0}")]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

#[derive(Debug)]
pub struct JsonCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    value: &'a JsonValue,
    direction: Direction,
}

impl<'a> JsonCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        value: &'a JsonValue,
        direction: Direction,
    ) -> Self {
        JsonCommitmentBuilder {
            builder,
            value,
            direction,
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
        let value = self.value.get(path).unwrap();

        let range = value.span().range();
        match self.direction {
            Direction::Sent => self.builder.commit_sent(range),
            Direction::Received => self.builder.commit_recv(range),
        }
        .map_err(From::from)
    }
}
