//! Types related to transcript commitments.

use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{substrings::SubstringsCommitment, Direction};

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
pub(crate) struct CommitmentInfo {
    pub(crate) ranges: RangeSet<usize>,
    pub(crate) direction: Direction,
}

impl CommitmentInfo {
    /// Creates a new transcript commitment details
    pub(crate) fn new(ranges: RangeSet<usize>, direction: Direction) -> Self {
        Self { ranges, direction }
    }

    /// Returns the ranges of this commitment
    pub(crate) fn ranges(&self) -> &RangeSet<usize> {
        &self.ranges
    }

    /// Returns the direction of this commitment
    pub(crate) fn direction(&self) -> &Direction {
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
