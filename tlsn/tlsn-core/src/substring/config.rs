use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use utils::range::{RangeSet, ToRangeSet};

use crate::{
    hash::HashAlgorithm, substring::SubstringCommitmentKind, transcript::SubsequenceIdx, Direction,
    Transcript,
};

/// Configuration for substring commitments.
#[derive(Debug, Clone)]
pub struct SubstringCommitConfig {
    encoding_hash_alg: HashAlgorithm,
    commits: Vec<(SubsequenceIdx, SubstringCommitmentKind)>,
}

impl SubstringCommitConfig {
    /// Returns the hash algorithm to use for encoding commitments.
    pub fn encoding_hash_alg(&self) -> &HashAlgorithm {
        &self.encoding_hash_alg
    }

    /// Returns whether the configuration has any encoding commitments.
    pub fn has_encoding(&self) -> bool {
        self.commits
            .iter()
            .any(|(_, kind)| matches!(kind, SubstringCommitmentKind::Encoding))
    }

    /// Returns an iterator over the encoding commitment indices.
    pub fn iter_encoding(&self) -> impl Iterator<Item = &SubsequenceIdx> {
        self.commits.iter().filter_map(|(idx, kind)| match kind {
            SubstringCommitmentKind::Encoding => Some(idx),
            _ => None,
        })
    }

    /// Returns an iterator over the hash commitment indices.
    pub fn iter_hash(&self) -> impl Iterator<Item = (&SubsequenceIdx, &HashAlgorithm)> {
        self.commits.iter().filter_map(|(idx, kind)| match kind {
            SubstringCommitmentKind::Hash { alg } => Some((idx, alg)),
            _ => None,
        })
    }
}

/// A error for [`SubstringCommitConfigBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum SubstringCommitConfigBuilderError {
    /// Attempted to commit to an empty range.
    #[error("attempted to commit to an empty range")]
    EmptyRange,
    /// Attempted to commit to a range that is out of bounds of the transcript.
    #[error("attempted to commit to a range that is out of bounds of transcript")]
    OutOfBounds {
        /// The commitment ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
        /// The transcript length.
        transcript_length: usize,
    },
}

/// A builder for [`SubstringCommitConfig`].
///
/// The default hash algorithm is [`HashAlgorithm::Blake3`] and the default kind
/// is [`SubstringCommitmentKind::Encoding`].
#[derive(Debug)]
pub struct SubstringCommitConfigBuilder {
    transcript: Transcript,
    encoding_hash_alg: HashAlgorithm,
    default_kind: SubstringCommitmentKind,
    // Hashset to prevent duplicates.
    commits: HashSet<(SubsequenceIdx, SubstringCommitmentKind)>,
}

impl SubstringCommitConfigBuilder {
    /// Creates a new commit config builder for the given transcript.
    pub fn new(transcript: &Transcript) -> Self {
        Self {
            transcript: transcript.clone(),
            encoding_hash_alg: HashAlgorithm::Blake3,
            default_kind: SubstringCommitmentKind::Encoding,
            commits: HashSet::default(),
        }
    }

    /// Sets the hash algorithm to use for encoding commitments.
    pub fn encoding_hash_alg(&mut self, alg: HashAlgorithm) -> &mut Self {
        self.encoding_hash_alg = alg;
        self
    }

    /// Sets the default kind of commitment to use.
    pub fn default_kind(&mut self, default_kind: SubstringCommitmentKind) -> &mut Self {
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
        kind: SubstringCommitmentKind,
    ) -> Result<&mut Self, SubstringCommitConfigBuilderError> {
        let seq = SubsequenceIdx {
            direction,
            ranges: ranges.to_range_set(),
        };

        if seq.ranges.is_empty() {
            return Err(SubstringCommitConfigBuilderError::EmptyRange);
        }

        if seq.ranges.end().expect("set not empty") > self.transcript.len_of_direction(direction) {
            return Err(SubstringCommitConfigBuilderError::OutOfBounds {
                ranges: seq.ranges.clone(),
                direction: seq.direction,
                transcript_length: self.transcript.len_of_direction(direction),
            });
        }

        self.commits.insert((seq, kind));

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
    ) -> Result<&mut Self, SubstringCommitConfigBuilderError> {
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
    ) -> Result<&mut Self, SubstringCommitConfigBuilderError> {
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
    ) -> Result<&mut Self, SubstringCommitConfigBuilderError> {
        self.commit(ranges, Direction::Received)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<SubstringCommitConfig, SubstringCommitConfigBuilderError> {
        Ok(SubstringCommitConfig {
            encoding_hash_alg: self.encoding_hash_alg,
            commits: Vec::from_iter(self.commits),
        })
    }
}

/// Configuration for a substrings proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstringProofConfig {
    pub(crate) seqs: Vec<SubsequenceIdx>,
}

impl SubstringProofConfig {
    /// Returns an iterator over the subsequence indices.
    pub fn iter(&self) -> impl Iterator<Item = &SubsequenceIdx> {
        self.seqs.iter()
    }
}

/// A error for [`SubstringProofConfigBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum SubstringProofConfigBuilderError {
    /// Attempted to prove an empty range.
    #[error("attempted to prove an empty range")]
    EmptyRange,
    /// Attempted to prove a range that is out of bounds of the transcript.
    #[error("attempted to prove a range that is out of bounds of transcript")]
    OutOfBounds {
        /// The ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
        /// The transcript length.
        transcript_length: usize,
    },
}

/// A builder for [`SubstringProofConfig`].
pub struct SubstringProofConfigBuilder {
    transcript: Transcript,
    seqs: HashSet<SubsequenceIdx>,
}

impl SubstringProofConfigBuilder {
    /// Creates a new proof config builder for the given transcript.
    pub fn new(transcript: &Transcript) -> Self {
        Self {
            transcript: transcript.clone(),
            seqs: HashSet::default(),
        }
    }

    /// Reveals the given ranges in the transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    /// * `direction` - The direction of the transcript.
    pub fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, SubstringProofConfigBuilderError> {
        let seq = SubsequenceIdx {
            direction,
            ranges: ranges.to_range_set(),
        };

        if seq.ranges.is_empty() {
            return Err(SubstringProofConfigBuilderError::EmptyRange);
        }

        if seq.ranges.end().expect("set not empty") > self.transcript.len_of_direction(direction) {
            return Err(SubstringProofConfigBuilderError::OutOfBounds {
                ranges: seq.ranges.clone(),
                direction: seq.direction,
                transcript_length: self.transcript.len_of_direction(direction),
            });
        }

        self.seqs.insert(seq);
        Ok(self)
    }

    /// Reveals the given ranges in the sent data transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, SubstringProofConfigBuilderError> {
        self.reveal(ranges, Direction::Sent)
    }

    /// Reveals the given ranges in the received data transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, SubstringProofConfigBuilderError> {
        self.reveal(ranges, Direction::Received)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<SubstringProofConfig, SubstringProofConfigBuilderError> {
        Ok(SubstringProofConfig {
            seqs: Vec::from_iter(self.seqs),
        })
    }
}
