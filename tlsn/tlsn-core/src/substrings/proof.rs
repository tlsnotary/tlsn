use std::collections::HashMap;

use mpz_circuits::types::ValueType;
use serde::{Deserialize, Serialize};
use utils::range::{RangeDisjoint, RangeSet, RangeUnion};

use crate::{
    commitment::{Commitment, CommitmentId, CommitmentInfo},
    error::Error,
    merkle::MerkleProof,
    transcript::{get_encoding_ids, TranscriptError},
    Direction, EncodingId, SessionData, SessionHeader, TranscriptSlice,
};

use mpz_garble_core::Encoder;

use super::opening::SubstringsOpening;

/// A builder for [`SubstringsProof`]
pub struct SubstringsProofBuilder<'a> {
    data: &'a SessionData,
    openings: HashMap<CommitmentId, (CommitmentInfo, SubstringsOpening)>,
}

opaque_debug::implement!(SubstringsProofBuilder<'_>);

/// An error for [`SubstringsProofBuilder`]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SubstringsProofBuilderError(String);

impl From<TranscriptError> for SubstringsProofBuilderError {
    fn from(e: TranscriptError) -> Self {
        Self(format!("transcript error: {}", e))
    }
}

impl<'a> SubstringsProofBuilder<'a> {
    /// Creates a new builder.
    pub(crate) fn new(data: &'a SessionData) -> Self {
        Self {
            data,
            openings: HashMap::default(),
        }
    }

    /// Reveals data corresponding to the provided commitment id
    pub fn reveal(&mut self, id: CommitmentId) -> Result<&mut Self, SubstringsProofBuilderError> {
        let (commitment, info) = self.data.commitments().get(&id).ok_or_else(|| {
            SubstringsProofBuilderError(format!("commitment with id {:?} not found", id))
        })?;

        #[allow(irrefutable_let_patterns)]
        let Commitment::Substrings(commitment) = commitment
        else {
            return Err(SubstringsProofBuilderError(format!(
                "commitment with id {:?} is not a substrings commitment",
                id
            )));
        };

        let data = match info.direction() {
            Direction::Sent => self
                .data
                .sent_transcript()
                .get_bytes_in_ranges(info.ranges())?,
            Direction::Received => self
                .data
                .recv_transcript()
                .get_bytes_in_ranges(info.ranges())?,
        };

        // check that the commitment is not already revealed
        if self
            .openings
            .insert(id, (info.clone(), commitment.open(data)))
            .is_some()
        {
            return Err(SubstringsProofBuilderError(format!(
                "commitment with id {:?} is already revealed",
                id
            )));
        }

        Ok(self)
    }

    /// Builds the [`SubstringsProof`]
    pub fn build(self) -> Result<SubstringsProof, SubstringsProofBuilderError> {
        let Self { data, openings } = self;

        let indices = openings
            .keys()
            .map(|id| id.into_inner() as usize)
            .collect::<Vec<_>>();

        let inclusion_proof = data.merkle_tree().proof(&indices);

        Ok(SubstringsProof {
            openings,
            inclusion_proof,
        })
    }
}

/// A substring proof containing the commitment openings and a proof
/// that the corresponding commitments are present in the merkle tree.
#[derive(Serialize, Deserialize)]
pub struct SubstringsProof {
    openings: HashMap<CommitmentId, (CommitmentInfo, SubstringsOpening)>,
    inclusion_proof: MerkleProof,
}

impl SubstringsProof {
    /// Verifies this proof and, if successful, returns [TranscriptSlice]s which were sent and
    /// received.
    pub fn verify(
        self,
        header: &SessionHeader,
    ) -> Result<(Vec<TranscriptSlice>, Vec<TranscriptSlice>), Error> {
        let Self {
            openings,
            inclusion_proof,
        } = self;

        let mut ids = Vec::with_capacity(openings.len());
        let mut indices = Vec::with_capacity(openings.len());
        let mut expected_hashes = Vec::with_capacity(openings.len());
        let mut sent_slices = Vec::new();
        let mut recv_slices = Vec::new();
        let mut sent_opened = RangeSet::default();
        let mut recv_opened = RangeSet::default();
        for (id, (info, opening)) in openings {
            let CommitmentInfo {
                ranges, direction, ..
            } = info;

            // Make sure duplicate data is not opened.
            match direction {
                Direction::Sent => {
                    if !sent_opened.is_disjoint(&ranges) {
                        panic!();
                    }
                    sent_opened = sent_opened.union(&ranges);
                }
                Direction::Received => {
                    if !recv_opened.is_disjoint(&ranges) {
                        panic!();
                    }
                    recv_opened = recv_opened.union(&ranges);
                }
            }

            ids.push(id);
            indices.push(id.into_inner() as usize);

            let encodings = get_encoding_ids(&ranges, direction)
                .map(|id| {
                    header
                        .encoder()
                        .encode_by_type(EncodingId::new(&id).to_inner(), &ValueType::U8)
                })
                .collect::<Vec<_>>();

            expected_hashes.push(opening.hash(&encodings).unwrap());

            let mut data = opening.into_data();

            // Make sure the length of data from the opening matches the commitment.
            if data.len() != ranges.len() {
                panic!();
            }

            let dest = match direction {
                Direction::Sent => &mut sent_slices,
                Direction::Received => &mut recv_slices,
            };

            // Split the data into slices corresponding to the ranges
            // and write it into the destination.
            for range in ranges.iter_ranges() {
                let len = range.len();
                dest.push(TranscriptSlice::new(range, data.drain(..len).collect()));
            }
        }

        // Verify that the expected hashes are present in the merkle tree.
        //
        // This proves that the Prover knew the encodings for the opened data prior to the
        // encoding seed being revealed.
        inclusion_proof.verify(header.merkle_root(), &indices, &expected_hashes)?;

        Ok((sent_slices, recv_slices))
    }
}
