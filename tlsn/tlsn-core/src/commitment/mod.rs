//! Types related to transcript commitments.

/// BLAKE3 commitments.
pub mod blake3;
mod builder;

use std::collections::HashMap;

use bimap::BiMap;
use mpz_core::hash::Hash;
use mpz_garble_core::{encoding_state::Full, EncodedValue};
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    merkle::{MerkleRoot, MerkleTree},
    Direction,
};

pub use builder::{TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError};

/// A commitment id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitmentId(u32);

impl CommitmentId {
    /// Creates a new commitment id
    pub(crate) fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the inner value
    pub(crate) fn to_inner(self) -> u32 {
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
    /// A BLAKE3 commitment to encodings of the transcript.
    Blake3(blake3::Blake3Commitment),
}

impl Commitment {
    /// Returns the hash of this commitment
    pub fn hash(&self) -> Hash {
        match self {
            Commitment::Blake3(commitment) => *commitment.hash(),
        }
    }

    /// Returns the kind of this commitment
    pub fn kind(&self) -> CommitmentKind {
        match self {
            Commitment::Blake3(_) => CommitmentKind::Blake3,
        }
    }
}

/// The kind of a [`Commitment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CommitmentKind {
    /// A BLAKE3 commitment to encodings of the transcript.
    Blake3,
}

/// An opening to a commitment to the transcript.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CommitmentOpening {
    /// An opening to a BLAKE3 commitment
    Blake3(blake3::Blake3Opening),
}

impl CommitmentOpening {
    /// Returns the kind of this opening
    pub fn kind(&self) -> CommitmentKind {
        match self {
            CommitmentOpening::Blake3(_) => CommitmentKind::Blake3,
        }
    }

    /// Recovers the expected commitment from this opening.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the following conditions are not met:
    ///
    /// - If the number of encodings does not match the number of bytes in the opening.
    /// - If an encoding is not for a u8.
    pub fn recover(&self, encodings: &[EncodedValue<Full>]) -> Commitment {
        match self {
            CommitmentOpening::Blake3(opening) => opening.recover(encodings).into(),
        }
    }

    /// Returns the transcript data corresponding to this opening
    pub fn data(&self) -> &[u8] {
        match self {
            CommitmentOpening::Blake3(opening) => opening.data(),
        }
    }

    /// Returns the transcript data corresponding to this opening
    pub fn into_data(self) -> Vec<u8> {
        match self {
            CommitmentOpening::Blake3(opening) => opening.into_data(),
        }
    }
}

/// A collection of transcript commitments.
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptCommitments {
    /// A Merkle tree of commitments. Each commitment's index in the tree matches its `CommitmentId`.
    merkle_tree: MerkleTree,
    commitments: HashMap<CommitmentId, Commitment>,
    /// Information about the above `commitments`.
    commitment_info: BiMap<CommitmentId, CommitmentInfo>,
}

opaque_debug::implement!(TranscriptCommitments);

impl TranscriptCommitments {
    /// Returns the merkle tree of the commitments.
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// Returns the merkle root of the commitments.
    pub fn merkle_root(&self) -> MerkleRoot {
        self.merkle_tree.root()
    }

    /// Returns a commitment if it exists.
    pub fn get(&self, id: &CommitmentId) -> Option<&Commitment> {
        self.commitments.get(id)
    }

    /// Returns the commitment id for a commitment with the given info, if it exists.
    pub fn get_id_by_info(
        &self,
        kind: CommitmentKind,
        ranges: &RangeSet<usize>,
        direction: Direction,
    ) -> Option<CommitmentId> {
        self.commitment_info
            .get_by_right(&CommitmentInfo::new(kind, ranges.clone(), direction))
            .copied()
    }

    /// Returns commitment info, if it exists.
    pub fn get_info(&self, id: &CommitmentId) -> Option<&CommitmentInfo> {
        self.commitment_info.get_by_left(id)
    }
}
