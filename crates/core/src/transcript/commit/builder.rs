use std::{collections::HashSet, fmt};

use rand::{distributions::Standard, prelude::Distribution, thread_rng};
use utils::range::ToRangeSet;

use crate::{
    hash::{Blinder, HashAlgId},
    transcript::{
        commit::{CommitInfo, SUPPORTED_PLAINTEXT_HASH_ALGS},
        Direction, Idx, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind,
    },
};

/// A builder for [`TranscriptCommitConfig`].
///
/// The default hash algorithm is [`HashAlgId::BLAKE3`] and the default kind
/// is [`TranscriptCommitmentKind::Encoding`].
#[derive(Debug)]
pub struct TranscriptCommitConfigBuilder<'a> {
    transcript: &'a Transcript,
    encoding_hash_alg: HashAlgId,
    default_kind: TranscriptCommitmentKind,
    /// Commitment information.
    commits: HashSet<CommitInfo>,
}

impl<'a> TranscriptCommitConfigBuilder<'a> {
    /// Creates a new commit config builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            encoding_hash_alg: HashAlgId::BLAKE3,
            default_kind: TranscriptCommitmentKind::Encoding,
            commits: HashSet::default(),
        }
    }

    /// Sets the hash algorithm to use for encoding commitments.
    pub fn encoding_hash_alg(&mut self, alg: HashAlgId) -> &mut Self {
        self.encoding_hash_alg = alg;
        self
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
        self.commit_with_kind_inner(ranges, direction, kind, None)
    }

    /// Adds a commitment with the default kind with a random blinder and returns the blinder.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges of the commitment.
    /// * `direction` - The direction of the transcript.
    pub fn commit_with_blinder(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<Blinder, TranscriptCommitConfigBuilderError> {
        let kind = self.default_kind;

        let TranscriptCommitmentKind::Hash { .. } = kind else {
            return Err(TranscriptCommitConfigBuilderError::new(
                ErrorKind::Algorithm,
                "commit_with_blinder is only supported for plaintext commitments",
            ));
        };

        let blinder: Blinder = Standard.sample(&mut thread_rng());

        self.commit_with_kind_inner(ranges, direction, kind, Some(blinder.clone()))?;

        Ok(blinder)
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
            encoding_hash_alg: self.encoding_hash_alg,
            commits: self.commits,
        })
    }

    /// Returns plaintext hash commitments.
    pub fn plaintext_hashes(&self) -> Vec<CommitInfo> {
        self.commits
            .iter()
            .filter_map(|commit| match commit.kind {
                TranscriptCommitmentKind::Hash { .. } => Some(commit.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    fn commit_with_kind_inner(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
        kind: TranscriptCommitmentKind,
        blinder: Option<Blinder>,
    ) -> Result<&mut Self, TranscriptCommitConfigBuilderError> {
        let idx = Idx::new(ranges.to_range_set());

        if idx.end() > self.transcript.len_of_direction(direction) {
            return Err(TranscriptCommitConfigBuilderError::new(
                ErrorKind::Index,
                format!(
                    "range is out of bounds of the transcript ({}): {} > {}",
                    direction,
                    idx.end(),
                    self.transcript.len_of_direction(direction)
                ),
            ));
        }

        if let TranscriptCommitmentKind::Hash { alg } = kind {
            if !SUPPORTED_PLAINTEXT_HASH_ALGS.contains(&alg) {
                return Err(TranscriptCommitConfigBuilderError::new(
                    ErrorKind::Algorithm,
                    format!("unsupported plaintext commitment algorithm {}", alg,),
                ));
            }
        }

        self.commits.insert(CommitInfo {
            idx: (direction, idx),
            kind,
            blinder,
        });

        Ok(self)
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
    Algorithm,
}

impl fmt::Display for TranscriptCommitConfigBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Index => f.write_str("index error")?,
            ErrorKind::Algorithm => f.write_str("algorithm error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
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
