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

/// An encoding commitment proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "validation::EncodingProofUnchecked")]
pub struct EncodingProof {
    /// The proof of inclusion of the commitment(s) in the Merkle tree of
    /// commitments.
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

            // Make sure the ranges are within the bounds of the transcript.
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

/// Invalid encoding proof error.
#[derive(Debug, thiserror::Error)]
#[error("invalid encoding proof: {0}")]
pub struct InvalidEncodingProof(&'static str);

mod validation {
    use super::*;

    /// The maximum allowed height of the Merkle tree of encoding commitments.
    ///
    /// The statistical security parameter (SSP) of the encoding commitment protocol is calculated
    /// as "the number of uniformly random bits in a single bit's encoding minus `MAX_HEIGHT`".
    ///
    /// For example, a bit encoding used in garbled circuits typically has 127 uniformly random
    /// bits, hence when using it in the encoding commitment protocol, the SSP is 117 bits.
    ///
    /// DO NOT use bit encodings which have less than 50 uniformly random bits, since the SSP < 40
    /// bits is widely considered inadequate.
    const MAX_HEIGHT: usize = 10;

    #[derive(Debug, Deserialize)]
    pub(super) struct EncodingProofUnchecked {
        inclusion_proof: MerkleProof,
        openings: HashMap<usize, Opening>,
    }

    impl TryFrom<EncodingProofUnchecked> for EncodingProof {
        type Error = InvalidEncodingProof;

        fn try_from(unchecked: EncodingProofUnchecked) -> Result<Self, Self::Error> {
            if unchecked.inclusion_proof.leaf_count() > 1 << MAX_HEIGHT {
                return Err(InvalidEncodingProof(
                    "the height of the tree exceeds the maximum allowed",
                ));
            }

            Ok(Self {
                inclusion_proof: unchecked.inclusion_proof,
                openings: unchecked.openings,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::{impl_domain_separator, Hash, HashAlgorithm, Sha256},
        merkle::MerkleTree,
    };

    #[derive(Serialize)]
    struct T(u64);

    impl_domain_separator!(T);

    fn leaves<H: HashAlgorithm>(hasher: &H, leaves: impl IntoIterator<Item = T>) -> Vec<Hash> {
        leaves
            .into_iter()
            .map(|x| hasher.hash_canonical(&x))
            .collect()
    }

    #[test]
    // Expect to fail since EncodingProof did not pass validation.
    fn test_proof_validation_fail() {
        let hasher = Sha256::default();

        let mut tree = MerkleTree::new(hasher.id());
        tree.insert(&hasher, leaves(&hasher, [T(0)]));

        let mut proof = tree.proof(&[0]);
        proof.set_leaf_count((1 << 20) + 1);

        let proof = EncodingProof {
            inclusion_proof: proof,
            openings: HashMap::default(),
        };

        let bytes = bincode::serialize(&proof).expect("proof should be serializable");

        let proof: Result<EncodingProof, Box<bincode::ErrorKind>> = bincode::deserialize(&bytes);
        assert!(proof.is_err())
    }
}
