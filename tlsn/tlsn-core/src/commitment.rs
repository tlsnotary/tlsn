//! Types related to transcript commitments.

use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    substrings::{SubstringsCommitment, SubstringsCommitmentKind},
    Direction,
};

/// A commitment id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitmentId(u32);

impl CommitmentId {
    /// Creates a new commitment id
    pub(crate) fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the inner value
    pub(crate) fn into_inner(self) -> u32 {
        self.0
    }
}

/// Info of a transcript commitment
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentInfo {
    pub(crate) kind: CommitmentKind,
    pub(crate) ranges: RangeSet<usize>,
    pub(crate) direction: Direction,
}

impl CommitmentInfo {
    /// Creates new commitment info.
    pub(crate) fn new(kind: CommitmentKind, ranges: RangeSet<usize>, direction: Direction) -> Self {
        Self {
            kind,
            ranges,
            direction,
        }
    }

    /// Returns the kind of this commitment
    pub fn kind(&self) -> CommitmentKind {
        self.kind
    }

    /// Returns the ranges of this commitment
    pub fn ranges(&self) -> &RangeSet<usize> {
        &self.ranges
    }

    /// Returns the direction of this commitment
    pub fn direction(&self) -> &Direction {
        &self.direction
    }
}

/// A commitment to some bytes in a transcript
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Commitment {
    /// A commitment to encodings of the transcript.
    Substrings(SubstringsCommitment),
}

impl Commitment {
    /// Returns the kind of this commitment
    pub fn kind(&self) -> CommitmentKind {
        match self {
            Commitment::Substrings(comm) => CommitmentKind::Substrings(comm.kind()),
        }
    }
}

/// The kind of a [`Commitment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CommitmentKind {
    /// A commitment to encodings of the transcript.
    Substrings(SubstringsCommitmentKind),
}
