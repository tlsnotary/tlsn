use crate::{commitment::Commitment, transcript::TranscriptRange, HashCommitment};
use serde::Serialize;

/// A User's commitment to one or multiple substrings of the notarized data
#[derive(Serialize, Clone, Default)]
pub struct SubstringsCommitment {
    /// The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    /// The actual commitment
    commitment: Commitment,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<TranscriptRange>,
    direction: Direction,
}

impl SubstringsCommitment {
    pub fn new(
        merkle_tree_index: u32,
        commitment: Commitment,
        ranges: Vec<TranscriptRange>,
        direction: Direction,
    ) -> Self {
        Self {
            merkle_tree_index,
            commitment,
            ranges,
            direction,
        }
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn commitment(&self) -> &Commitment {
        &self.commitment
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
