use crate::{commitment::Commitment, error::Error, transcript::Direction};
use mpz_core::commit::Nonce;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use utils::iter::DuplicateCheck;

#[cfg(feature = "tracing")]
use tracing::instrument;

/// A set of commitments
#[derive(Default, Serialize, Deserialize)]
pub struct SubstringsCommitmentSet(Vec<SubstringsCommitment>);

impl SubstringsCommitmentSet {
    /// Creates a new commitment set
    pub fn new(comms: Vec<SubstringsCommitment>) -> Self {
        Self(comms)
    }

    /// Validate the commitment set
    ///
    /// Ensures that:
    /// - each individual commitment is valid
    /// - the set is not empty
    /// - the merkle_tree_index of each commitment is unique
    /// - the grand total in all of the commitments' ranges is sane
    #[cfg_attr(feature = "tracing", instrument(level = "trace", skip(self), err))]
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
        if ids.iter().contains_dups() {
            return Err(Error::ValidationError);
        }

        // grand total in all of the commitments' ranges must be sane
        let mut total_committed = 0u64;
        for commitment in &self.0 {
            for r in commitment.ranges() {
                total_committed += (r.end - r.start) as u64;
                if total_committed > crate::MAX_TOTAL_COMMITTED_DATA {
                    return Err(Error::ValidationError);
                }
            }
        }

        Ok(())
    }

    /// Checks if the commitment set is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of commitments in this set
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the commitments
    pub fn iter(&self) -> std::slice::Iter<SubstringsCommitment> {
        self.0.iter()
    }
}

/// A Prover's commitment to one or multiple substrings of the [crate::Transcript]
#[derive(Serialize, Deserialize, Clone)]
pub struct SubstringsCommitment {
    /// The index of this commitment in the Merkle tree of commitments.
    /// Also serves as a unique id for this commitment.
    merkle_tree_index: u32,
    /// The actual commitment
    commitment: Commitment,
    /// The absolute byte ranges within the [crate::Transcript]. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<Range<u32>>,
    direction: Direction,
    /// Randomness used to salt the commitment
    salt: Nonce,
}

impl SubstringsCommitment {
    /// Creates a new commitment to substrings
    pub fn new(
        merkle_tree_index: u32,
        commitment: Commitment,
        ranges: Vec<Range<u32>>,
        direction: Direction,
        salt: Nonce,
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
    ///
    /// Ensures that:
    /// - at least one range is expected
    /// - ranges are valid
    /// - ranges do not overlap and are ascending
    /// - grand total in all the commitment's ranges is sane
    pub fn validate(&self) -> Result<(), Error> {
        // at least one range is expected
        if self.ranges().is_empty() {
            return Err(Error::ValidationError);
        }

        for r in self.ranges() {
            // ranges must be valid
            if r.end <= r.start {
                return Err(Error::ValidationError);
            }
        }

        // ranges must not overlap and must be ascending relative to each other
        for pair in self.ranges().windows(2) {
            if pair[1].start < pair[0].end {
                return Err(Error::ValidationError);
            }
        }

        // grand total in all the commitment's ranges must be sane
        let mut total_in_ranges = 0u64;
        for r in self.ranges() {
            total_in_ranges += (r.end - r.start) as u64;
            if total_in_ranges > crate::MAX_TOTAL_COMMITTED_DATA {
                return Err(Error::ValidationError);
            }
        }

        Ok(())
    }

    /// Returns the index of this commitment in the Merkle tree
    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    /// Returns the actual commitment
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Returns the ranges of bytes in the transcript this commitment refers to
    pub fn ranges(&self) -> &[Range<u32>] {
        &self.ranges
    }

    /// Returns the direction, i.e. if the commitment refers to data sent or received
    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    /// Returns the salt used for this commitment
    pub fn salt(&self) -> &Nonce {
        &self.salt
    }
}
