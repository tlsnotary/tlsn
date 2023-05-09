use crate::{
    commitment::Commitment,
    error::Error,
    transcript::{Direction, TranscriptRange},
    utils::has_unique_elements,
};
use serde::{Deserialize, Serialize};

/// A set of commitments
#[derive(Default, Serialize, Deserialize)]
pub struct SubstringsCommitmentSet(Vec<SubstringsCommitment>);

impl SubstringsCommitmentSet {
    pub fn new(comms: Vec<SubstringsCommitment>) -> Self {
        Self(comms)
    }

    // Validate the set
    pub fn validate(&self) -> Result<(), Error> {
        // validate each individual commitment
        for c in &self.0 {
            c.validate()?;
        }

        // the set must not be empty
        if self.is_empty() {
            return Err(Error::ValidationError);
        }

        // merkle_tree_index of each commitment must be unique
        let ids: Vec<u32> = self.0.iter().map(|c| c.merkle_tree_index()).collect();
        if !has_unique_elements(ids) {
            return Err(Error::ValidationError);
        }

        // grand total in all of the commitments' ranges must be sane
        let mut total_committed = 0u64;
        for commitment in &self.0 {
            for r in commitment.ranges() {
                total_committed += (r.end() - r.start()) as u64;
                if total_committed > crate::MAX_TOTAL_COMMITTED_DATA {
                    return Err(Error::ValidationError);
                }
            }
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<SubstringsCommitment> {
        self.0.iter()
    }
}

/// A User's commitment to one or multiple substrings of the [crate::Transcript]
#[derive(Serialize, Deserialize, Clone)]
pub struct SubstringsCommitment {
    /// The index of this commitment in the Merkle tree of commitments.
    /// Also serves as a unique id for this commitment.
    merkle_tree_index: u32,
    /// The actual commitment
    commitment: Commitment,
    /// The absolute byte ranges within the [crate::Transcript]. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<TranscriptRange>,
    direction: Direction,
    /// Randomness used to salt the commitment
    salt: [u8; 16],
}

impl SubstringsCommitment {
    pub fn new(
        merkle_tree_index: u32,
        commitment: Commitment,
        ranges: Vec<TranscriptRange>,
        direction: Direction,
        salt: [u8; 16],
    ) -> Self {
        Self {
            merkle_tree_index,
            commitment,
            ranges,
            direction,
            salt,
        }
    }

    /// Validates this commitment
    pub fn validate(&self) -> Result<(), Error> {
        let len = self.ranges().len();
        // at least one range is expected
        if len == 0 {
            return Err(Error::ValidationError);
        }

        for r in self.ranges() {
            // ranges must be valid
            if r.end() <= r.start() {
                return Err(Error::ValidationError);
            }
        }

        // ranges must not overlap and must be ascending relative to each other
        for pair in self.ranges().windows(2) {
            if pair[1].start() < pair[0].end() {
                return Err(Error::ValidationError);
            }
        }

        // grand total in all the commitment's ranges must be sane
        let mut total_in_ranges = 0u64;
        for r in self.ranges() {
            total_in_ranges += (r.end() - r.start()) as u64;
            if total_in_ranges > crate::MAX_TOTAL_COMMITTED_DATA {
                return Err(Error::ValidationError);
            }
        }

        Ok(())
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

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
}
