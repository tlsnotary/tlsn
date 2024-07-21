//! Substrings proofs based on commitments.

use crate::{
    commitment::{
        Commitment, CommitmentId, CommitmentInfo, CommitmentKind, CommitmentOpening,
        TranscriptCommitments,
    },
    merkle::MerkleProof,
    transcript::get_value_ids,
    Direction, EncodingId, RedactedTranscript, SessionHeader, Transcript, TranscriptSlice,
    MAX_TOTAL_COMMITTED_DATA,
};
use mpz_circuits::types::ValueType;
use mpz_garble_core::Encoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utils::range::{RangeDisjoint, RangeSet, RangeUnion, ToRangeSet};

/// An error for [`SubstringsProofBuilder`]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringsProofBuilderError {
    /// Invalid commitment id.
    #[error("invalid commitment id: {0:?}")]
    InvalidCommitmentId(CommitmentId),
    /// Missing commitment.
    #[error("missing commitment")]
    MissingCommitment,
    /// Invalid commitment type.
    #[error("commitment {0:?} is not a substrings commitment")]
    InvalidCommitmentType(CommitmentId),
    /// Attempted to add a commitment with a duplicate id.
    #[error("commitment with id {0:?} already exists")]
    DuplicateCommitmentId(CommitmentId),
}

/// A builder for [`SubstringsProof`]
pub struct SubstringsProofBuilder<'a> {
    commitments: &'a TranscriptCommitments,
    transcript_tx: &'a Transcript,
    transcript_rx: &'a Transcript,
    openings: HashMap<CommitmentId, (CommitmentInfo, CommitmentOpening)>,
}

opaque_debug::implement!(SubstringsProofBuilder<'_>);

impl<'a> SubstringsProofBuilder<'a> {
    /// Creates a new builder.
    pub fn new(
        commitments: &'a TranscriptCommitments,
        transcript_tx: &'a Transcript,
        transcript_rx: &'a Transcript,
    ) -> Self {
        Self {
            commitments,
            transcript_tx,
            transcript_rx,
            openings: HashMap::default(),
        }
    }

    /// Returns a reference to the commitments.
    pub fn commitments(&self) -> &TranscriptCommitments {
        self.commitments
    }

    /// Reveals data corresponding to the provided ranges in the sent direction.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        commitment_kind: CommitmentKind,
    ) -> Result<&mut Self, SubstringsProofBuilderError> {
        self.reveal(ranges, Direction::Sent, commitment_kind)
    }

    /// Reveals data corresponding to the provided transcript subsequence in the received direction.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        commitment_kind: CommitmentKind,
    ) -> Result<&mut Self, SubstringsProofBuilderError> {
        self.reveal(ranges, Direction::Received, commitment_kind)
    }

    /// Reveals data corresponding to the provided ranges and direction.
    pub fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
        commitment_kind: CommitmentKind,
    ) -> Result<&mut Self, SubstringsProofBuilderError> {
        let com = self
            .commitments
            .get_id_by_info(commitment_kind, &ranges.to_range_set(), direction)
            .ok_or(SubstringsProofBuilderError::MissingCommitment)?;

        self.reveal_by_id(com)
    }

    /// Reveals data corresponding to the provided commitment id
    pub fn reveal_by_id(
        &mut self,
        id: CommitmentId,
    ) -> Result<&mut Self, SubstringsProofBuilderError> {
        let commitment = self
            .commitments()
            .get(&id)
            .ok_or(SubstringsProofBuilderError::InvalidCommitmentId(id))?;

        let info = self
            .commitments()
            .get_info(&id)
            .expect("info exists if commitment exists");

        #[allow(irrefutable_let_patterns)]
        let Commitment::Blake3(commitment) = commitment
        else {
            return Err(SubstringsProofBuilderError::InvalidCommitmentType(id));
        };

        let transcript = match info.direction() {
            Direction::Sent => self.transcript_tx,
            Direction::Received => self.transcript_rx,
        };

        let data = transcript.get_bytes_in_ranges(info.ranges());

        // add commitment to openings and return an error if it is already present
        if self
            .openings
            .insert(id, (info.clone(), commitment.open(data).into()))
            .is_some()
        {
            return Err(SubstringsProofBuilderError::DuplicateCommitmentId(id));
        }

        Ok(self)
    }

    /// Builds the [`SubstringsProof`]
    pub fn build(self) -> Result<SubstringsProof, SubstringsProofBuilderError> {
        let Self {
            commitments,
            openings,
            ..
        } = self;

        let mut indices = openings
            .keys()
            .map(|id| id.to_inner() as usize)
            .collect::<Vec<_>>();
        indices.sort();

        let inclusion_proof = commitments.merkle_tree().proof(&indices);

        Ok(SubstringsProof {
            openings,
            inclusion_proof,
        })
    }
}

/// An error relating to [`SubstringsProof`]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringsProofError {
    /// The proof contains more data than the maximum allowed.
    #[error(
        "substrings proof opens more data than the maximum allowed: {0} > {}",
        MAX_TOTAL_COMMITTED_DATA
    )]
    MaxDataExceeded(usize),
    /// The proof contains duplicate transcript data.
    #[error("proof contains duplicate transcript data")]
    DuplicateData(Direction, RangeSet<usize>),
    /// Range of the opening is out of bounds.
    #[error("range of opening {0:?} is out of bounds: {1}")]
    RangeOutOfBounds(CommitmentId, usize),
    /// The proof contains an invalid commitment opening.
    #[error("invalid opening for commitment id: {0:?}")]
    InvalidOpening(CommitmentId),
    /// The proof contains an invalid inclusion proof.
    #[error("invalid inclusion proof: {0}")]
    InvalidInclusionProof(String),
}

/// A substring proof using commitments
///
/// This substring proof contains the commitment openings and a proof
/// that the corresponding commitments are present in the merkle tree.
#[derive(Serialize, Deserialize)]
pub struct SubstringsProof {
    openings: HashMap<CommitmentId, (CommitmentInfo, CommitmentOpening)>,
    inclusion_proof: MerkleProof,
}

opaque_debug::implement!(SubstringsProof);

impl SubstringsProof {
    /// Verifies this proof and, if successful, returns the redacted sent and received transcripts.
    ///
    /// # Arguments
    ///
    /// * `header` - The session header.
    pub fn verify(
        self,
        header: &SessionHeader,
    ) -> Result<(RedactedTranscript, RedactedTranscript), SubstringsProofError> {
        let Self {
            openings,
            inclusion_proof,
        } = self;

        let mut indices = Vec::with_capacity(openings.len());
        let mut expected_hashes = Vec::with_capacity(openings.len());
        let mut sent = vec![0u8; header.sent_len()];
        let mut recv = vec![0u8; header.recv_len()];
        let mut sent_ranges = RangeSet::default();
        let mut recv_ranges = RangeSet::default();
        let mut total_opened = 0u128;
        for (id, (info, opening)) in openings {
            let CommitmentInfo {
                ranges, direction, ..
            } = info;

            let opened_len = ranges.len();

            // Make sure the amount of data being proved is bounded.
            total_opened += opened_len as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(SubstringsProofError::MaxDataExceeded(total_opened as usize));
            }

            // Make sure the opening length matches the ranges length.
            if opening.data().len() != opened_len {
                return Err(SubstringsProofError::InvalidOpening(id));
            }

            // Make sure duplicate data is not opened.
            match direction {
                Direction::Sent => {
                    if !sent_ranges.is_disjoint(&ranges) {
                        return Err(SubstringsProofError::DuplicateData(direction, ranges));
                    }
                    sent_ranges = sent_ranges.union(&ranges);
                }
                Direction::Received => {
                    if !recv_ranges.is_disjoint(&ranges) {
                        return Err(SubstringsProofError::DuplicateData(direction, ranges));
                    }
                    recv_ranges = recv_ranges.union(&ranges);
                }
            }

            // Make sure the ranges are within the bounds of the transcript
            let max = ranges
                .max()
                .ok_or(SubstringsProofError::InvalidOpening(id))?;
            let transcript_len = match direction {
                Direction::Sent => header.sent_len(),
                Direction::Received => header.recv_len(),
            };

            if max > transcript_len {
                return Err(SubstringsProofError::RangeOutOfBounds(id, max));
            }

            // Generate the expected encodings for the purported data in the opening.
            let encodings = get_value_ids(&ranges, direction)
                .map(|id| {
                    header
                        .encoder()
                        .encode_by_type(EncodingId::new(&id).to_inner(), &ValueType::U8)
                })
                .collect::<Vec<_>>();

            // Compute the expected hash of the commitment to make sure it is
            // present in the merkle tree.
            indices.push(id.to_inner() as usize);
            expected_hashes.push(opening.recover(&encodings).hash());

            // Make sure the length of data from the opening matches the commitment.
            let mut data = opening.into_data();
            if data.len() != ranges.len() {
                return Err(SubstringsProofError::InvalidOpening(id));
            }

            let dest = match direction {
                Direction::Sent => &mut sent,
                Direction::Received => &mut recv,
            };

            // Iterate over the ranges backwards, copying the data from the opening
            // then truncating it.
            for range in ranges.iter_ranges().rev() {
                let start = data.len() - range.len();
                dest[range].copy_from_slice(&data[start..]);
                data.truncate(start);
            }
        }

        // Verify that the expected hashes are present in the merkle tree.
        //
        // This proves the Prover committed to the purported data prior to the encoder
        // seed being revealed.
        inclusion_proof
            .verify(header.merkle_root(), &indices, &expected_hashes)
            .map_err(|e| SubstringsProofError::InvalidInclusionProof(e.to_string()))?;

        // Iterate over the unioned ranges and create TranscriptSlices for each.
        // This ensures that the slices are sorted and disjoint.
        let sent_slices = sent_ranges
            .iter_ranges()
            .map(|range| TranscriptSlice::new(range.clone(), sent[range].to_vec()))
            .collect();
        let recv_slices = recv_ranges
            .iter_ranges()
            .map(|range| TranscriptSlice::new(range.clone(), recv[range].to_vec()))
            .collect();

        Ok((
            RedactedTranscript::new(header.sent_len(), sent_slices),
            RedactedTranscript::new(header.recv_len(), recv_slices),
        ))
    }
}
