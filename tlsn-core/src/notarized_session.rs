use serde::Serialize;

use crate::{
    commitment::{self, Commitment},
    error::Error,
    inclusion_proof::InclusionProof,
    merkle::MerkleProof,
    session_data::SessionData,
    session_header::SessionHeader,
    signature::Signature,
    substrings_commitment::SubstringsCommitment,
    substrings_opening::{Blake3Opening, SubstringsOpening},
    substrings_proof::SubstringsProof,
};
use rs_merkle::{algorithms::Sha256, MerkleTree};

#[derive(Serialize)]
pub struct NotarizedSession {
    version: u8,
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

impl NotarizedSession {
    pub fn new(
        version: u8,
        header: SessionHeader,
        signature: Option<Signature>,
        data: SessionData,
    ) -> Self {
        Self {
            version,
            header,
            signature,
            data,
        }
    }

    /// Generates a `SubstringsProof` for commitments with the provided merkle tree indices
    pub fn generate_substring_proof(&self, indices: Vec<usize>) -> Result<SubstringsProof, Error> {
        let merkle_tree_leaf_count = self.data.commitments().len();

        // TODO: check that indices are unique

        let commitments: Vec<SubstringsCommitment> = self
            .data
            .commitments()
            .iter()
            .filter_map(|com| {
                if indices.contains(&(com.merkle_tree_index() as usize)) {
                    Some(com.clone())
                } else {
                    None
                }
            })
            .collect();

        // if leaf count equals commitment count, all indices were valid
        if indices.len() != commitments.len() {
            return Err(Error::InternalError);
        }

        let merkle_proof = MerkleProof(self.data().merkle_tree().0.proof(&indices));

        let mut openings: Vec<SubstringsOpening> = Vec::with_capacity(commitments.len());
        for com in &commitments {
            let bytes: Vec<u8> = self
                .data()
                .transcript()
                .get_bytes_in_ranges(com.ranges(), com.direction())?;

            match com.commitment() {
                Commitment::Blake3(_) => {
                    let opening = Blake3Opening::new(
                        com.merkle_tree_index(),
                        bytes,
                        com.ranges(),
                        com.direction().clone(),
                    );
                    openings.push(SubstringsOpening::Blake3(opening));
                }
            };
        }

        let inclusion_proof =
            InclusionProof::new(commitments, merkle_proof, merkle_tree_leaf_count as u32);

        Ok(SubstringsProof::new(openings, inclusion_proof))
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    pub fn signature(&self) -> &Option<Signature> {
        &self.signature
    }

    pub fn data(&self) -> &SessionData {
        &self.data
    }
}
