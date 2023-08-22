use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error, utils::merge_slices, Direction, InclusionProof, SessionHeader,
    SubstringsCommitment, SubstringsOpeningSet, TranscriptSlice,
};

#[cfg(feature = "tracing")]
use tracing::instrument;

/// A substring proof containing the opening set and the inclusion proof
#[derive(Serialize, Deserialize)]
pub struct SubstringsProof {
    openings: SubstringsOpeningSet,
    inclusion_proof: InclusionProof,
}

impl SubstringsProof {
    /// Creates a new substring proof
    pub fn new(openings: SubstringsOpeningSet, inclusion_proof: InclusionProof) -> Self {
        Self {
            openings,
            inclusion_proof,
        }
    }

    /// Verifies this proof and, if successful, returns [TranscriptSlice]s which were sent and
    /// received.
    #[cfg_attr(feature = "tracing", instrument(level = "trace", skip(self), err))]
    pub fn verify(
        self,
        header: &SessionHeader,
    ) -> Result<(Vec<TranscriptSlice>, Vec<TranscriptSlice>), Error> {
        self.validate(header)?;

        let commitments = self.inclusion_proof.verify(header.merkle_root())?;

        // pre-allocate to the max possible capacity
        let mut sent_slices: Vec<TranscriptSlice> = Vec::with_capacity(commitments.len());
        let mut recv_slices: Vec<TranscriptSlice> = Vec::with_capacity(commitments.len());

        // verify each opening against the corresponding commitment
        for opening in self.openings.iter() {
            let commitment = commitments
                .get(&opening.merkle_tree_index())
                .expect("commitment should be present");

            let opening_slices = opening.verify(header, commitment)?;

            if opening.direction() == &Direction::Sent {
                sent_slices.extend(opening_slices);
            } else {
                recv_slices.extend(opening_slices);
            }
        }

        Ok((merge_slices(sent_slices)?, merge_slices(recv_slices)?))
    }

    // Validates `self` and all its nested types
    fn validate(&self, header: &SessionHeader) -> Result<(), Error> {
        self.inclusion_proof.validate()?;
        self.openings.validate()?;

        // range bound must not exceed total data sent/received
        for comm in self.inclusion_proof.commitments().iter() {
            if comm.direction() == &Direction::Sent {
                for r in comm.ranges() {
                    if r.end > header.sent_len() {
                        return Err(Error::ValidationError);
                    }
                }
            } else {
                // comm.direction() == &Direction::Received
                for r in comm.ranges() {
                    if r.end > header.recv_len() {
                        return Err(Error::ValidationError);
                    }
                }
            }
        }

        // validate openings against commitments:

        // commitment and opening count must match
        if self.inclusion_proof.commitments().len() != self.openings.len() {
            return Err(Error::ValidationError);
        }

        // build a <merkle tree index, SubstringsCommitment> hashmap
        let mut map: HashMap<u32, &SubstringsCommitment> = HashMap::new();
        for c in self.inclusion_proof.commitments().iter() {
            map.insert(c.merkle_tree_index(), c);
        }

        // make sure relevant fields match for each opening-commitment pair
        for o in self.openings.iter() {
            let Some(c) = map.get(&o.merkle_tree_index()) else {
                // `merkle_tree_index` doesn't match
                return Err(Error::ValidationError);
            };

            // directions must match
            if o.direction() != c.direction() {
                return Err(Error::ValidationError);
            }

            // range count must match
            if o.ranges().len() != c.ranges().len() {
                return Err(Error::ValidationError);
            }

            // each individual range must match
            for i in 0..o.ranges().len() {
                if o.ranges()[i] != c.ranges()[i] {
                    return Err(Error::ValidationError);
                }
            }
        }

        Ok(())
    }
}
