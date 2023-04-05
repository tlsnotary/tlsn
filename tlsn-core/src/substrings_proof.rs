use crate::{
    error::Error, inclusion_proof::InclusionProof, substrings_opening::SubstringsOpening,
    transcript::TranscriptSlice, SessionHeader,
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

    pub fn verify(&self, header: &SessionHeader) -> Result<Vec<TranscriptSlice>, Error> {
        let commitments = self.inclusion_proof.verify(header)?;

        // TODO check that there are no dup openings with the same id

        let mut slices: Vec<TranscriptSlice> = Vec::with_capacity(commitments.len());
        for opening in &self.openings {
            let Some(commitment) = commitments.get(&opening.merkle_tree_index()) else {
                return Err(Error::InternalError)
            };

            let opening_slices = opening.verify(header, commitment)?;

            slices.extend(opening_slices);
        }

        Ok(slices)
    }
}
