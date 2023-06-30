mod artifacts;
mod data;
mod header;
mod proof;

use serde::{Deserialize, Serialize};
use utils::iter::DuplicateCheck;

pub use artifacts::SessionArtifacts;
pub use data::SessionData;
pub use header::SessionHeader;
pub use proof::SessionProof;

use crate::{
    error::Error,
    signature::Signature,
    substrings::{
        opening::{Blake3Opening, SubstringsOpening, SubstringsOpeningSet},
        proof::SubstringsProof,
    },
    Commitment, Direction, InclusionProof, SubstringsCommitment, SubstringsCommitmentSet,
};

#[derive(Serialize, Deserialize)]
pub struct NotarizedSession {
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

impl NotarizedSession {
    pub fn new(header: SessionHeader, signature: Option<Signature>, data: SessionData) -> Self {
        Self {
            header,
            signature,
            data,
        }
    }

    /// Generates a `SubstringsProof` for commitments with the provided merkle tree indices
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, indices), err)
    )]
    pub fn generate_substring_proof(&self, indices: Vec<usize>) -> Result<SubstringsProof, Error> {
        // check that merkle tree indices are unique
        if indices.iter().contains_dups() {
            return Err(Error::WrongMerkleTreeIndices);
        }

        // pick only those commitments which have the provided `indices`
        let commitments: Vec<SubstringsCommitment> = self
            .data
            .commitments()
            .iter()
            .filter_map(|com| {
                if indices.contains(&(com.merkle_tree_index() as usize)) {
                    Some(com.clone())
                } else {
                    // no value will be yielded
                    None
                }
            })
            .collect();

        // the amount of picked commitments must be equal to the amount of `indices`
        if indices.len() != commitments.len() {
            return Err(Error::WrongMerkleTreeIndices);
        }

        let merkle_proof = self.data().merkle_tree().proof(&indices);

        // create an opening for each commitment
        let mut openings: Vec<SubstringsOpening> = Vec::with_capacity(commitments.len());
        for com in &commitments {
            let transcript = if com.direction() == &Direction::Sent {
                self.data().sent_transcript()
            } else {
                self.data().recv_transcript()
            };

            let bytes: Vec<u8> = transcript.get_bytes_in_ranges(com.ranges())?;

            match com.commitment() {
                Commitment::Blake3(_) => {
                    let opening = Blake3Opening::new(
                        com.merkle_tree_index(),
                        bytes,
                        com.ranges(),
                        com.direction().clone(),
                        *com.salt(),
                    );
                    openings.push(SubstringsOpening::Blake3(opening));
                }
            };
        }

        let inclusion_proof = InclusionProof::new(
            SubstringsCommitmentSet::new(commitments),
            merkle_proof,
            self.data.commitments().len() as u32,
        );

        Ok(SubstringsProof::new(
            SubstringsOpeningSet::new(openings),
            inclusion_proof,
        ))
    }

    pub fn session_proof(&self) -> SessionProof {
        SessionProof::new(
            self.header().clone(),
            self.signature().clone(),
            self.data().handshake_data_decommitment().clone(),
        )
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
