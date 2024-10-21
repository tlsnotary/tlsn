use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    connection::TranscriptLength,
    hash::{Blinded, Blinder, HashAlgorithmExt, HashProviderError},
    merkle::{MerkleError, MerkleProof},
    transcript::{
        encoding::{
            new_encoder, tree::EncodingLeaf, Encoder, EncodingCommitment, MAX_TOTAL_COMMITTED_DATA,
        },
        Direction, PartialTranscript, Subsequence,
    },
    CryptoProvider,
};

/// An opening of a leaf in the encoding tree.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Opening {
    pub(super) direction: Direction,
    pub(super) seq: Subsequence,
    pub(super) blinder: Blinder,
}

opaque_debug::implement!(Opening);

/// An encoding proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        transcript_length: &TranscriptLength,
        commitment: &EncodingCommitment,
    ) -> Result<PartialTranscript, EncodingProofError> {
        let hasher = provider.hash.get(&commitment.root.alg)?;

        let seed: [u8; 32] = commitment.seed.clone().try_into().map_err(|_| {
            EncodingProofError::new(ErrorKind::Commitment, "encoding seed not 32 bytes")
        })?;

        let encoder = new_encoder(seed);
        let Self {
            inclusion_proof,
            openings,
        } = self;
        let (sent_len, recv_len) = (
            transcript_length.sent as usize,
            transcript_length.received as usize,
        );

        let mut leaves = Vec::with_capacity(openings.len());
        let mut transcript = PartialTranscript::new(sent_len, recv_len);
        let mut total_opened = 0u128;
        for (
            id,
            Opening {
                direction,
                seq,
                blinder,
            },
        ) in openings
        {
            // Make sure the amount of data being proved is bounded.
            total_opened += seq.len() as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(EncodingProofError::new(
                    ErrorKind::Proof,
                    "exceeded maximum allowed data",
                ))?;
            }

            // Make sure the ranges are within the bounds of the transcript
            let transcript_len = match direction {
                Direction::Sent => sent_len,
                Direction::Received => recv_len,
            };

            if seq.index().end() > transcript_len {
                return Err(EncodingProofError::new(
                    ErrorKind::Proof,
                    format!(
                        "index out of bounds of the transcript ({}): {} > {}",
                        direction,
                        seq.index().end(),
                        transcript_len
                    ),
                ));
            }

            let expected_encoding = encoder.encode_subsequence(direction, &seq);
            let expected_leaf =
                Blinded::new_with_blinder(EncodingLeaf::new(expected_encoding), blinder);

            // Compute the expected hash of the commitment to make sure it is
            // present in the merkle tree.
            leaves.push((id, hasher.hash_canonical(&expected_leaf)));

            // Union the authenticated subsequence into the transcript.
            transcript.union_subsequence(direction, &seq);
        }

        // Verify that the expected hashes are present in the merkle tree.
        //
        // This proves the Prover committed to the purported data prior to the encoder
        // seed being revealed. Ergo, if the encodings are authentic then the purported
        // data is authentic.
        inclusion_proof.verify(hasher, &commitment.root, leaves)?;

        Ok(transcript)
    }
}

/// Error for [`EncodingProof`].
#[derive(Debug, thiserror::Error)]
pub struct EncodingProofError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl EncodingProofError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Provider,
    Commitment,
    Proof,
}

impl fmt::Display for EncodingProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("encoding proof error: ")?;

        match self.kind {
            ErrorKind::Provider => f.write_str("provider error")?,
            ErrorKind::Commitment => f.write_str("commitment error")?,
            ErrorKind::Proof => f.write_str("proof error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<HashProviderError> for EncodingProofError {
    fn from(error: HashProviderError) -> Self {
        Self::new(ErrorKind::Provider, error)
    }
}

impl From<MerkleError> for EncodingProofError {
    fn from(error: MerkleError) -> Self {
        Self::new(ErrorKind::Proof, error)
    }
}

#[cfg(test)]
mod test {
    use tlsn_data_fixtures::http::{request::POST_JSON, response::OK_JSON};

    use crate::{
        fixtures::{encoder_seed, encoding_provider},
        hash::Blake3,
        transcript::{encoding::EncodingTree, Idx, Transcript},
    };

    use super::*;

    struct TestFixture {
        transcript: Transcript,
        proof: EncodingProof,
        commitment: EncodingCommitment,
    }

    fn new_test_fixture(seed: Vec<u8>) -> TestFixture {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let idx_0 = (Direction::Sent, Idx::new(0..POST_JSON.len()));
        let idx_1 = (Direction::Received, Idx::new(0..OK_JSON.len()));

        let provider = encoding_provider(transcript.sent(), transcript.received());
        let transcript_length = TranscriptLength {
            sent: transcript.sent().len() as u32,
            received: transcript.received().len() as u32,
        };
        let tree = EncodingTree::new(
            &Blake3::default(),
            [&idx_0, &idx_1],
            &provider,
            &transcript_length,
        )
        .unwrap();

        let proof = tree
            .proof(&transcript, [&idx_0, &idx_1].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed,
        };

        TestFixture {
            transcript,
            proof,
            commitment,
        }
    }

    #[test]
    fn test_verify_encoding_proof_invalid_seed() {
        let TestFixture {
            transcript,
            proof,
            commitment,
        } = new_test_fixture(encoder_seed().to_vec().split_off(1));

        let err = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &transcript.length(),
                &commitment,
            )
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Commitment));
    }

    #[test]
    fn test_verify_encoding_proof_out_of_range() {
        let TestFixture {
            transcript,
            proof,
            commitment,
        } = new_test_fixture(encoder_seed().to_vec());

        let err = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &TranscriptLength {
                    sent: (transcript.len_of_direction(Direction::Sent) - 1) as u32,
                    received: (transcript.len_of_direction(Direction::Received) - 2) as u32,
                },
                &commitment,
            )
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Proof));
    }

    #[test]
    fn test_verify_encoding_proof_tampered_encoding_seq() {
        let TestFixture {
            transcript,
            mut proof,
            commitment,
        } = new_test_fixture(encoder_seed().to_vec());

        let Opening { seq, .. } = proof.openings.values_mut().next().unwrap();

        *seq = Subsequence::new(Idx::new([0..3, 13..15]), [0, 1, 2, 5, 6].into()).unwrap();

        let err = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &transcript.length(),
                &commitment,
            )
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Proof));
    }

    #[test]
    fn test_verify_encoding_proof_tampered_encoding_blinder() {
        let TestFixture {
            transcript,
            mut proof,
            commitment,
        } = new_test_fixture(encoder_seed().to_vec());

        let Opening { blinder, .. } = proof.openings.values_mut().next().unwrap();

        *blinder = rand::random();

        let err = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &transcript.length(),
                &commitment,
            )
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Proof));
    }
}
