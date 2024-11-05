//! Transcript commitments.

mod builder;

use std::collections::HashSet;

use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::{
    hash::{Blinder, HashAlgId},
    transcript::{Direction, Idx, Transcript},
};

pub use builder::{TranscriptCommitConfigBuilder, TranscriptCommitConfigBuilderError};

#[cfg(feature = "poseidon")]
pub(crate) const SUPPORTED_PLAINTEXT_HASH_ALGS: &[HashAlgId] = &[HashAlgId::POSEIDON_BN256_434];

#[cfg(not(feature = "poseidon"))]
pub(crate) const SUPPORTED_PLAINTEXT_HASH_ALGS: &[HashAlgId] = &[];

/// Kind of transcript commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TranscriptCommitmentKind {
    /// A commitment to encodings of the transcript.
    Encoding,
    /// A hash commitment to plaintext in the transcript.
    Hash {
        /// The hash algorithm used.
        alg: HashAlgId,
    },
}

/// Configuration for transcript commitments.
#[derive(Debug, Clone)]
pub struct TranscriptCommitConfig {
    encoding_hash_alg: HashAlgId,
    /// Commitment information.
    commits: HashSet<CommitInfo>,
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

    /// Returns whether the configuration has any encoding commitments.
    pub fn has_encoding(&self) -> bool {
        self.commits
            .iter()
            .any(|commit| matches!(commit.kind, TranscriptCommitmentKind::Encoding))
    }

    /// Returns an iterator over the encoding commitment indices.
    pub fn iter_encoding(&self) -> impl Iterator<Item = &(Direction, Idx)> {
        self.commits.iter().filter_map(|commit| match commit.kind {
            TranscriptCommitmentKind::Encoding => Some(&commit.idx),
            _ => None,
        })
    }

    /// Returns whether the configuration has any plaintext hash commitments.
    pub fn has_plaintext_hashes(&self) -> bool {
        self.commits
            .iter()
            .any(|commit| matches!(commit.kind, TranscriptCommitmentKind::Hash { .. }))
    }

    /// Returns the plaintext hash commitment info.
    pub fn plaintext_hashes(&self) -> Vec<CommitInfo> {
        self.commits
            .iter()
            .filter_map(|commit| match commit.kind {
                TranscriptCommitmentKind::Hash { .. } => Some(commit.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }
}

/// The information required to create a commitment to a subset of transcript data.
#[derive(Debug, Clone, Eq, PartialEq, Getters, std::hash::Hash)]
pub struct CommitInfo {
    /// The index of data in a transcript.
    #[getset(get = "pub")]
    idx: (Direction, Idx),
    /// The commitment kind.
    #[getset(get = "pub")]
    kind: TranscriptCommitmentKind,
    /// The blinder to use for the commitment.
    ///
    /// None value means that the blinder will be generated later at the time of creating the
    /// commitment.
    #[getset(get = "pub")]
    blinder: Option<Blinder>,
}
