use crate::{
    commitment::{Blake3, Commitment},
    error::Error,
    utils::merge_slices,
    Direction, EncodingId, SessionHeader, Transcript, TranscriptSlice,
};
use mpc_circuits::types::ValueType;
use mpc_core::commit::{Decommitment, Nonce};
use mpc_garble_core::{encoding_state::Active, EncodedValue, Encoder};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use utils::iter::DuplicateCheck;

/// A set of openings
#[derive(Serialize, Deserialize)]
pub struct SubstringsOpeningSet(Vec<SubstringsOpening>);

impl SubstringsOpeningSet {
    pub fn new(openings: Vec<SubstringsOpening>) -> Self {
        Self(openings)
    }

    // Validate the set
    pub fn validate(&self) -> Result<(), Error> {
        // --- validate each individual opening
        for c in &self.0 {
            c.validate()?;
        }

        // --- the set must not be empty
        if self.is_empty() {
            return Err(Error::ValidationError);
        }

        // --- merkle_tree_index of each opening must be unique
        let ids: Vec<u32> = self.0.iter().map(|o| o.merkle_tree_index()).collect();
        if ids.iter().contains_dups() {
            return Err(Error::ValidationError);
        }

        // --- the total of all openings' bytes must not be too large
        let mut total_opening_bytes = 0u64;
        for o in &self.0 {
            total_opening_bytes += o.opening().len() as u64;
            if total_opening_bytes > crate::MAX_TOTAL_COMMITTED_DATA {
                return Err(Error::ValidationError);
            }
        }

        // --- overlapping ranges must contain the same data:

        // pre-allocate to the approx capacity
        let mut sent_slices: Vec<TranscriptSlice> = Vec::with_capacity(self.len());
        let mut recv_slices: Vec<TranscriptSlice> = Vec::with_capacity(self.len());

        // split up each opening into slices
        for o in self.iter() {
            if o.direction() == &Direction::Sent {
                let s = o.clone().as_slices();
                sent_slices.extend(s);
            } else {
                recv_slices.extend(o.clone().as_slices());
            }
        }

        // trying to merge the slices will return an error if the overlapping slices don't
        // contain the exact data
        _ = merge_slices(sent_slices)?;
        _ = merge_slices(recv_slices)?;

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<SubstringsOpening> {
        self.0.iter()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum SubstringsOpening {
    Blake3(Blake3Opening),
}

impl SubstringsOpening {
    pub fn verify(
        &self,
        header: &SessionHeader,
        commitment: &Commitment,
    ) -> Result<Vec<TranscriptSlice>, Error> {
        match (&self, commitment) {
            (SubstringsOpening::Blake3(opening), Commitment::Blake3(comm)) => {
                // instantiate an empty transcript in order to derive the encoding ids
                let id = match opening.direction() {
                    Direction::Sent => "tx",
                    Direction::Received => "rx",
                };
                let transcript = Transcript::new(id, vec![]);

                // collect active encodings for each byte in each range
                let active_encodings: Vec<EncodedValue<Active>> = opening
                    .ranges()
                    .iter()
                    .flat_map(|range| {
                        transcript
                            .get_ids(range)
                            .into_iter()
                            .map(|id| {
                                header
                                    .encoder()
                                    .encode_by_type(EncodingId::new(&id).to_inner(), &ValueType::U8)
                            })
                            // collect full encodings
                            .collect::<Vec<_>>()
                    })
                    .zip(opening.opening())
                    .map(|(enc, value)| enc.select(*value).unwrap())
                    .collect();

                opening.verify(active_encodings, comm)?;
            }
        }
        Ok(self.as_slices())
    }

    /// Validates this opening
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            SubstringsOpening::Blake3(opening) => opening.validate()?,
        }

        Ok(())
    }

    pub fn opening(&self) -> &[u8] {
        match self {
            SubstringsOpening::Blake3(opening) => opening.opening(),
        }
    }

    pub fn merkle_tree_index(&self) -> u32 {
        match self {
            SubstringsOpening::Blake3(opening) => opening.merkle_tree_index(),
        }
    }

    pub fn direction(&self) -> &Direction {
        match self {
            SubstringsOpening::Blake3(opening) => opening.direction(),
        }
    }

    pub fn ranges(&self) -> &[Range<u32>] {
        match self {
            SubstringsOpening::Blake3(opening) => opening.ranges(),
        }
    }

    /// Returns the opening split up into [TranscriptSlice]s
    fn as_slices(&self) -> Vec<TranscriptSlice> {
        // clone the opening because we will be draining it
        let mut opening = self.opening().to_vec();

        self.ranges()
            .iter()
            .map(|r| {
                let range_len = (r.end - r.start) as usize;
                TranscriptSlice::new(r.clone(), opening.drain(0..range_len).collect())
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Blake3Opening {
    /// The index of this commitment in the Merkle tree of commitments.
    /// Also serves as a unique id for this opening.
    merkle_tree_index: u32,
    /// The actual opening bytes
    opening: Vec<u8>,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<Range<u32>>,
    direction: Direction,
    /// Randomness used to salt the commitment
    salt: Nonce,
}

impl Blake3Opening {
    pub fn new(
        merkle_tree_index: u32,
        opening: Vec<u8>,
        ranges: &[Range<u32>],
        direction: Direction,
        salt: Nonce,
    ) -> Self {
        Self {
            merkle_tree_index,
            opening,
            ranges: ranges.to_vec(),
            direction,
            salt,
        }
    }

    /// Verify the encodings against the commitment
    pub fn verify(
        &self,
        encodings: Vec<EncodedValue<Active>>,
        commitment: &Blake3,
    ) -> Result<(), Error> {
        // create a decommitment and verify it against the commitment
        Decommitment::new_with_nonce(encodings, self.salt)
            .verify(commitment.encoding_hash())
            .map_err(|_| Error::OpeningVerificationFailed)
    }

    /// Validates this opening
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

        // the total length of all ranges must be sane
        let mut total_len = 0u64;
        for r in self.ranges() {
            total_len += (r.end - r.start) as u64;
            if total_len > crate::MAX_TOTAL_COMMITTED_DATA {
                return Err(Error::ValidationError);
            }
        }

        // opening's bytecount must match the total length of all ranges
        if self.opening.len() as u64 != total_len {
            return Err(Error::ValidationError);
        }

        Ok(())
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn opening(&self) -> &[u8] {
        &self.opening
    }

    pub fn ranges(&self) -> &[Range<u32>] {
        &self.ranges
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }
}
