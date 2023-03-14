use crate::{transcript::TranscriptRange, HashCommitment};
use serde::Serialize;

/// A User's commitment to a portion of the notarized data
#[derive(Serialize, Clone, Default)]
pub struct Commitment {
    /// The actual commitment
    commitment: HashCommitment,
    typ: CommitmentType,
    direction: Direction,
    /// The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<TranscriptRange>,
}

impl Commitment {
    pub fn new(
        typ: CommitmentType,
        direction: Direction,
        commitment: HashCommitment,
        ranges: Vec<TranscriptRange>,
        merkle_tree_index: u32,
    ) -> Self {
        Self {
            typ,
            direction,
            commitment,
            ranges,
            merkle_tree_index,
        }
    }

    pub fn typ(&self) -> &CommitmentType {
        &self.typ
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn ranges(&self) -> &[TranscriptRange] {
        &self.ranges
    }
}

#[derive(Clone, PartialEq, Serialize, Default)]
#[allow(non_camel_case_types)]
pub enum CommitmentType {
    #[default]
    // A blake3 digest of the garbled circuit's active labels. The labels are generated from a PRG seed.
    // For more details on the protocol used to generate this commitment, see
    // https://github.com/tlsnotary/docs-mdbook/blob/main/src/protocol/notarization/public_data_commitment.md
    labels_blake3,
}

#[derive(Serialize, Clone, PartialEq, Default, Debug)]
/// A TLS transcript consists of a stream of bytes which were `Sent` to the server
/// and a stream of bytes which were `Received` from the server . The User creates
/// separate commitments to bytes in each direction.
pub enum Direction {
    #[default]
    Sent,
    Received,
}
