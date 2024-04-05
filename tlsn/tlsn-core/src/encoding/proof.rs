use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    conn::TranscriptLength,
    encoding::{
        new_encoder, tree::EncodingLeaf, Encoder, EncodingCommitment, MAX_TOTAL_COMMITTED_DATA,
    },
    hash::HashAlgorithm,
    merkle::MerkleProof,
    transcript::{PartialTranscript, Subsequence},
    Direction,
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
    pub(super) seq: Subsequence,
    pub(super) nonce: [u8; 16],
}

opaque_debug::implement!(Opening);

/// An encoding proof.
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
    ) -> Result<PartialTranscript, EncodingProofError> {
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
        let mut transcript = PartialTranscript::new(sent_len, recv_len);
        let mut total_opened = 0u128;
        for (id, Opening { seq, nonce }) in openings {
            // Make sure the amount of data being proved is bounded.
            total_opened += seq.len() as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(EncodingProofError::ExceededMaxData);
            }

            // Make sure the ranges are within the bounds of the transcript
            let transcript_len = match seq.index().direction() {
                Direction::Sent => sent_len,
                Direction::Received => recv_len,
            };

            if seq.index().end() > transcript_len as usize {
                return Err(EncodingProofError::OutOfBounds {
                    input_end: seq.index().end(),
                    transcript_length: transcript_len,
                    direction: seq.index().direction(),
                });
            }

            let expected_encoding = encoder.encode_subsequence(&seq);
            let expected_leaf = EncodingLeaf::new(expected_encoding, nonce);

            // Compute the expected hash of the commitment to make sure it is
            // present in the merkle tree.
            indices.push(id);
            leafs.push(expected_leaf);

            // Union the authenticated subsequence into the transcript.
            transcript.union_subsequence(&seq);
        }

        // Verify that the expected hashes are present in the merkle tree.
        //
        // This proves the Prover committed to the purported data prior to the encoder
        // seed being revealed. Ergo, if the encodings are authentic then the purported
        // data is authentic.
        inclusion_proof
            .verify(&commitment.root, &indices, &leafs)
            .map_err(|_| EncodingProofError::MissingCommitment)?;

        Ok(transcript)
    }
}
