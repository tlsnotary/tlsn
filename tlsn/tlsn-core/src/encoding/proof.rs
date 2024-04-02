use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utils::range::{RangeDisjoint, RangeSet, RangeUnion};

use crate::{
    conn::TranscriptLength,
    encoding::{
        new_encoder, tree::EncodingLeaf, Encoder, EncodingCommitment, MAX_TOTAL_COMMITTED_DATA,
    },
    hash::HashAlgorithm,
    merkle::MerkleProof,
    transcript::{PartialTranscript, SliceIdx, SubsequenceIdx},
    Direction, Slice,
};

/// Encoding proof error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingProofError {
    /// Encoder seed in the commitment is invalid.
    #[error("encoder seed in the commitment is invalid")]
    InvalidSeed,
    /// Proof attempts to prove an empty range.
    #[error("proof attempts to prove an empty range")]
    EmptyRange,
    /// Proof attempts to prove data outside the bounds of the transcript.
    #[error(
        "proof attempts to prove data outside the bounds of the transcript: \
        {direction:?} {input_end} > {transcript_length}"
    )]
    OutOfBounds {
        input_end: usize,
        transcript_length: usize,
        direction: Direction,
    },
    /// Proof attempts to open a commitment which is not in the tree.
    #[error("proof attempts to open a commitment which is not in the tree")]
    MissingCommitment,
    /// Proof uses the wrong hash algorithm.
    #[error("proof uses the wrong hash algorithm: expected {expected:?}, got {actual:?}")]
    WrongHashAlgorithm {
        /// The expected hash algorithm.
        expected: HashAlgorithm,
        /// The actual hash algorithm.
        actual: HashAlgorithm,
    },
    /// Proof attempts to open more data than the maximum allowed.
    #[error("proof attempts to open more data than the maximum allowed")]
    ExceededMaxData,
    /// Proof is malformed.
    #[error("proof is malformed")]
    Malformed,
    /// Proof contains duplicate data.
    #[error("proof contains duplicate data")]
    DuplicateData,
}

/// An opening of a leaf in the encoding tree.
#[derive(Serialize, Deserialize)]
pub(super) struct Opening {
    seq: SubsequenceIdx,
    data: Vec<u8>,
    nonce: [u8; 16],
}

opaque_debug::implement!(Opening);

impl Opening {
    pub(super) fn new(seq: SubsequenceIdx, data: Vec<u8>, nonce: [u8; 16]) -> Self {
        assert_eq!(data.len(), seq.ranges.len(), "data length mismatch");
        Self { seq, data, nonce }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncodingProof {
    pub(super) inclusion_proof: MerkleProof,
    pub(super) openings: HashMap<usize, Opening>,
}

impl EncodingProof {
    /// Verifies the proof against the commitment.
    ///
    /// Returns the partial sent and received transcripts, respectively.
    ///
    /// # Arguments
    ///
    /// * `transcript_length` - The length of the transcript.
    /// * `commitment` - The encoding commitment to verify against.
    pub fn verify(
        self,
        transcript_length: &TranscriptLength,
        commitment: &EncodingCommitment,
    ) -> Result<(PartialTranscript, PartialTranscript), EncodingProofError> {
        let seed: [u8; 32] = commitment
            .seed
            .clone()
            .try_into()
            .map_err(|_| EncodingProofError::InvalidSeed)?;

        let encoder = new_encoder(seed);
        let Self {
            inclusion_proof,
            openings,
        } = self;
        let (sent_len, recv_len) = (
            transcript_length.sent as usize,
            transcript_length.received as usize,
        );

        let mut indices = Vec::with_capacity(openings.len());
        let mut leafs = Vec::with_capacity(openings.len());
        let mut sent = vec![0u8; sent_len as usize];
        let mut recv = vec![0u8; recv_len as usize];
        let mut sent_ranges = RangeSet::default();
        let mut recv_ranges = RangeSet::default();
        let mut total_opened = 0u128;
        for (
            id,
            Opening {
                seq,
                mut data,
                nonce,
            },
        ) in openings
        {
            let opened_len = seq.ranges.len();

            // Make sure the amount of data being proved is bounded.
            total_opened += opened_len as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(EncodingProofError::ExceededMaxData);
            }

            // Make sure the opening length matches the ranges length.
            if data.len() != opened_len {
                return Err(EncodingProofError::Malformed);
            }

            // Make sure duplicate data is not opened.
            match seq.direction {
                Direction::Sent => {
                    if !sent_ranges.is_disjoint(&seq.ranges) {
                        return Err(EncodingProofError::DuplicateData);
                    }
                    sent_ranges = sent_ranges.union(&seq.ranges);
                }
                Direction::Received => {
                    if !recv_ranges.is_disjoint(&seq.ranges) {
                        return Err(EncodingProofError::DuplicateData);
                    }
                    recv_ranges = recv_ranges.union(&seq.ranges);
                }
            }

            // Make sure the ranges are within the bounds of the transcript
            let end = seq.ranges.end().ok_or(EncodingProofError::EmptyRange)?;
            let transcript_len = match seq.direction {
                Direction::Sent => sent_len,
                Direction::Received => recv_len,
            };

            if end > transcript_len as usize {
                return Err(EncodingProofError::OutOfBounds {
                    input_end: end,
                    transcript_length: transcript_len,
                    direction: seq.direction,
                });
            }

            let expected_encoding = encoder.encode_subsequence(&seq, &data);
            let expected_leaf = EncodingLeaf::new(expected_encoding, nonce);

            // Compute the expected hash of the commitment to make sure it is
            // present in the merkle tree.
            indices.push(id);
            leafs.push(expected_leaf);

            let dest = match seq.direction {
                Direction::Sent => &mut sent,
                Direction::Received => &mut recv,
            };

            // Iterate over the ranges backwards, copying the data from the opening
            // then truncating it.
            for range in seq.ranges.iter_ranges().rev() {
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
            .verify(&commitment.root, &indices, &leafs)
            .map_err(|_| EncodingProofError::MissingCommitment)?;

        // Iterate over the unioned ranges and create TranscriptSlices for each.
        // This ensures that the slices are sorted and disjoint.
        let mut sent_slices = sent_ranges
            .iter_ranges()
            .map(|range| {
                Slice::new(
                    SliceIdx {
                        direction: Direction::Sent,
                        range: range.clone(),
                    },
                    sent[range].to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let mut recv_slices = recv_ranges
            .iter_ranges()
            .map(|range| {
                Slice::new(
                    SliceIdx {
                        direction: Direction::Received,
                        range: range.clone(),
                    },
                    recv[range].to_vec(),
                )
            })
            .collect::<Vec<_>>();

        sent_slices.sort_by_key(|slice| slice.index().range.start);
        recv_slices.sort_by_key(|slice| slice.index().range.start);

        Ok((
            PartialTranscript::new(sent_len, sent_slices),
            PartialTranscript::new(recv_len, recv_slices),
        ))
    }
}
