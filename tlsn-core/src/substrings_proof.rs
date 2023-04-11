use crate::{
    error::Error, inclusion_proof::InclusionProof, substrings_commitment::Direction,
    substrings_opening::SubstringsOpening, transcript::TranscriptSlice, SessionHeader,
};

pub struct SubstringsProof {
    openings: Vec<SubstringsOpening>,
    inclusion_proof: InclusionProof,
}

impl SubstringsProof {
    pub fn new(openings: Vec<SubstringsOpening>, inclusion_proof: InclusionProof) -> Self {
        Self {
            openings,
            inclusion_proof,
        }
    }

    pub fn verify(
        &self,
        header: &SessionHeader,
    ) -> Result<(Vec<TranscriptSlice>, Vec<TranscriptSlice>), Error> {
        let commitments = self.inclusion_proof.verify(header)?;

        // TODO check that there are no dup openings with the same id

        let mut sent_slices: Vec<TranscriptSlice> = Vec::with_capacity(commitments.len());
        let mut recv_slices: Vec<TranscriptSlice> = Vec::with_capacity(commitments.len());

        for opening in &self.openings {
            let Some(commitment) = commitments.get(&opening.merkle_tree_index()) else {
                return Err(Error::InternalError)
            };

            let opening_slices = opening.verify(header, commitment)?;

            if opening.direction() == &Direction::Sent {
                sent_slices.extend(opening_slices);
            } else {
                recv_slices.extend(opening_slices);
            }
        }

        // TODO sort slices in ascending order, check any overlap
        // TODO check that last slice's `range.end()` does not exceed

        Ok((sent_slices, recv_slices))
    }
}
