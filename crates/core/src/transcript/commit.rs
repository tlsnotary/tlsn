//! Transcript commitments.

use std::{collections::HashSet, fmt};

use rangeset::set::ToRangeSet;
use serde::{Deserialize, Serialize};

use crate::{
    hash::HashAlgId,
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, RangeSet, Transcript,
    },
};

/// Kind of transcript commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptCommitmentKind {
    /// A hash commitment to plaintext in the transcript.
    Hash {
        /// The hash algorithm used.
        alg: HashAlgId,
    },
}

impl fmt::Display for TranscriptCommitmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash { alg } => write!(f, "hash ({alg})"),
        }
    }
}

/// Transcript commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptCommitment {
    /// Plaintext hash commitment.
    Hash(PlaintextHash),
}

/// Secret for a transcript commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptSecret {
    /// Plaintext hash secret.
    Hash(PlaintextHashSecret),
}

/// Configuration for transcript commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptCommitConfig {
    commits: Vec<((Direction, RangeSet<usize>), TranscriptCommitmentKind)>,
}

impl TranscriptCommitConfig {
    /// Creates a new commit config builder.
    pub fn builder(transcript: &Transcript) -> TranscriptCommitConfigBuilder<'_> {
        TranscriptCommitConfigBuilder::new(transcript)
    }

    /// Returns `true` if the configuration has any hash commitments.
    pub fn has_hash(&self) -> bool {
        self.commits
            .iter()
            .any(|(_, kind)| matches!(kind, TranscriptCommitmentKind::Hash { .. }))
    }

    /// Returns an iterator over the hash commitment indices.
    pub fn iter_hash(&self) -> impl Iterator<Item = (&(Direction, RangeSet<usize>), &HashAlgId)> {
        self.commits.iter().map(|(idx, kind)| match kind {
            TranscriptCommitmentKind::Hash { alg } => (idx, alg),
        })
    }

    /// Returns a request for the transcript commitments.
    pub fn to_request(&self) -> TranscriptCommitRequest {
        TranscriptCommitRequest {
            hash: self
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect(),
        }
    }
}

/// A builder for [`TranscriptCommitConfig`].
#[derive(Debug)]
pub struct TranscriptCommitConfigBuilder<'a> {
    transcript: &'a Transcript,
    default_kind: TranscriptCommitmentKind,
    commits: HashSet<((Direction, RangeSet<usize>), TranscriptCommitmentKind)>,
}

impl<'a> TranscriptCommitConfigBuilder<'a> {
    /// Creates a new commit config builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            default_kind: TranscriptCommitmentKind::Hash {
                alg: HashAlgId::BLAKE3,
            },
            commits: HashSet::default(),
        }
    }

    /// Sets the default kind of commitment to use.
    pub fn default_kind(&mut self, default_kind: TranscriptCommitmentKind) -> &mut Self {
        self.default_kind = default_kind;
        self
    }

    /// Adds a commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    /// * `direction` - The direction of the transcript.
    /// * `kind` - The kind of commitment.
    pub fn commit_with_kind(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
        kind: TranscriptCommitmentKind,
    ) -> Result<&mut Self, TranscriptCommitConfigBuilderError> {
        let idx = ranges.to_range_set();

        if idx.end().unwrap_or(0) > self.transcript.len_of_direction(direction) {
            return Err(TranscriptCommitConfigBuilderError::new(
                ErrorKind::Index,
                format!(
                    "range is out of bounds of the transcript ({}): {} > {}",
                    direction,
                    idx.end().unwrap_or(0),
                    self.transcript.len_of_direction(direction)
                ),
            ));
        }

        self.commits.insert(((direction, idx), kind));

        Ok(self)
    }

    /// Adds a commitment with the default kind.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    /// * `direction` - The direction of the transcript.
    pub fn commit(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, TranscriptCommitConfigBuilderError> {
        self.commit_with_kind(ranges, direction, self.default_kind)
    }

    /// Adds a commitment with the default kind to the sent data transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    pub fn commit_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptCommitConfigBuilderError> {
        self.commit(ranges, Direction::Sent)
    }

    /// Adds a commitment with the default kind to the received data transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    pub fn commit_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptCommitConfigBuilderError> {
        self.commit(ranges, Direction::Received)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<TranscriptCommitConfig, TranscriptCommitConfigBuilderError> {
        Ok(TranscriptCommitConfig {
            commits: Vec::from_iter(self.commits),
        })
    }
}

/// Error for [`TranscriptCommitConfigBuilder`].
#[derive(Debug, thiserror::Error)]
pub struct TranscriptCommitConfigBuilderError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TranscriptCommitConfigBuilderError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Index,
}

impl fmt::Display for TranscriptCommitConfigBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Index => f.write_str("index error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

/// Request to compute transcript commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptCommitRequest {
    hash: Vec<(Direction, RangeSet<usize>, HashAlgId)>,
}

impl TranscriptCommitRequest {
    /// Returns `true` if a hash commitment is requested.
    pub fn has_hash(&self) -> bool {
        !self.hash.is_empty()
    }

    /// Returns an iterator over the hash commitments.
    pub fn iter_hash(&self) -> impl Iterator<Item = &(Direction, RangeSet<usize>, HashAlgId)> {
        self.hash.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_out_of_bounds() {
        let transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        let mut builder = TranscriptCommitConfigBuilder::new(&transcript);

        assert!(builder.commit_sent(&(10..15)).is_err());
        assert!(builder.commit_recv(&(10..15)).is_err());
    }
}
