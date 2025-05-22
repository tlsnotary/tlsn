//! Transcript commitments.

use std::{collections::HashSet, fmt};

use rangeset::ToRangeSet;
use serde::{Deserialize, Serialize};

use crate::{
    hash::{impl_domain_separator, HashAlgId},
    transcript::{
        encoding::{EncodingCommitment, EncodingTree},
        hash::{PlaintextHash, PlaintextHashSecret},
        Direction, Idx, Transcript,
    },
};

/// The maximum allowed total bytelength of committed data for a single
/// commitment kind. Used to prevent DoS during verification. (May cause the
/// verifier to hash up to a max of 1GB * 128 = 128GB of data for certain kinds
/// of encoding commitments.)
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 <<
/// 31) - 1 by default)
pub(crate) const MAX_TOTAL_COMMITTED_DATA: usize = 1_000_000_000;

/// Kind of transcript commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptCommitmentKind {
    /// A commitment to encodings of the transcript.
    Encoding,
    /// A hash commitment to plaintext in the transcript.
    Hash {
        /// The hash algorithm used.
        alg: HashAlgId,
    },
}

impl fmt::Display for TranscriptCommitmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => f.write_str("encoding"),
            Self::Hash { alg } => write!(f, "hash ({alg})"),
        }
    }
}

/// Transcript commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptCommitment {
    /// Encoding commitment.
    Encoding(EncodingCommitment),
    /// Plaintext hash commitment.
    Hash(PlaintextHash),
}

impl_domain_separator!(TranscriptCommitment);

/// Secret for a transcript commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranscriptSecret {
    /// Encoding tree.
    Encoding(EncodingTree),
    /// Plaintext hash secret.
    Hash(PlaintextHashSecret),
}

impl_domain_separator!(TranscriptSecret);

/// Configuration for transcript commitments.
#[derive(Debug, Clone)]
pub struct TranscriptCommitConfig {
    encoding_hash_alg: HashAlgId,
    has_encoding: bool,
    has_hash: bool,
    commits: Vec<((Direction, Idx), TranscriptCommitmentKind)>,
}

impl TranscriptCommitConfig {
    /// Creates a new commit config builder.
    pub fn builder(transcript: &Transcript) -> TranscriptCommitConfigBuilder {
        TranscriptCommitConfigBuilder::new(transcript)
    }

    /// Returns the hash algorithm to use for encoding commitments.
    pub fn encoding_hash_alg(&self) -> &HashAlgId {
        &self.encoding_hash_alg
    }

    /// Returns `true` if the configuration has any encoding commitments.
    pub fn has_encoding(&self) -> bool {
        self.has_encoding
    }

    /// Returns `true` if the configuration has any hash commitments.
    pub fn has_hash(&self) -> bool {
        self.has_hash
    }

    /// Returns an iterator over the encoding commitment indices.
    pub fn iter_encoding(&self) -> impl Iterator<Item = &(Direction, Idx)> {
        self.commits.iter().filter_map(|(idx, kind)| match kind {
            TranscriptCommitmentKind::Encoding => Some(idx),
            _ => None,
        })
    }

    /// Returns an iterator over the hash commitment indices.
    pub fn iter_hash(&self) -> impl Iterator<Item = (&(Direction, Idx), &HashAlgId)> {
        self.commits.iter().filter_map(|(idx, kind)| match kind {
            TranscriptCommitmentKind::Hash { alg } => Some((idx, alg)),
            _ => None,
        })
    }

    /// Returns a request for the transcript commitments.
    pub fn to_request(&self) -> TranscriptCommitRequest {
        TranscriptCommitRequest {
            encoding: self.has_encoding,
            hash: self
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect(),
        }
    }
}

/// A builder for [`TranscriptCommitConfig`].
///
/// The default hash algorithm is [`HashAlgId::BLAKE3`] and the default kind
/// is [`TranscriptCommitmentKind::Encoding`].
#[derive(Debug)]
pub struct TranscriptCommitConfigBuilder<'a> {
    transcript: &'a Transcript,
    encoding_hash_alg: HashAlgId,
    has_encoding: bool,
    has_hash: bool,
    default_kind: TranscriptCommitmentKind,
    commits: HashSet<((Direction, Idx), TranscriptCommitmentKind)>,
}

impl<'a> TranscriptCommitConfigBuilder<'a> {
    /// Creates a new commit config builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            encoding_hash_alg: HashAlgId::BLAKE3,
            has_encoding: false,
            has_hash: false,
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

        match kind {
            TranscriptCommitmentKind::Encoding => self.has_encoding = true,
            TranscriptCommitmentKind::Hash { .. } => self.has_hash = true,
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
            encoding_hash_alg: self.encoding_hash_alg,
            has_encoding: self.has_encoding,
            has_hash: self.has_hash,
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
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

/// Request to compute transcript commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptCommitRequest {
    encoding: bool,
    hash: Vec<(Direction, Idx, HashAlgId)>,
}

impl TranscriptCommitRequest {
    /// Returns `true` if an encoding commitment is requested.
    pub fn encoding(&self) -> bool {
        self.encoding
    }

    /// Returns `true` if a hash commitment is requested.
    pub fn has_hash(&self) -> bool {
        !self.hash.is_empty()
    }

    /// Returns an iterator over the hash commitments.
    pub fn iter_hash(&self) -> impl Iterator<Item = &(Direction, Idx, HashAlgId)> {
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
