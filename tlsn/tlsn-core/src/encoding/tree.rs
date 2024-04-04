use std::collections::HashMap;

use bimap::BiMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    conn::TranscriptLength,
    encoding::{
        proof::{EncodingProof, Opening},
        EncodingProvider,
    },
    hash::{Hash, HashAlgorithm},
    merkle::MerkleTree,
    transcript::{Subsequence, SubsequenceIdx},
    Direction, Transcript,
};

/// Encoding tree builder error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingTreeError {
    /// Attempted to commit to an empty range.
    #[error("attempted to commit to an empty range")]
    EmptyRange,
    /// Range is out of bounds of the transcript.
    #[error(
        "range is out of bounds of the transcript: \
        {input_end} > {transcript_length}"
    )]
    OutOfBounds {
        /// The end of the input range.
        input_end: usize,
        /// The transcript length.
        transcript_length: usize,
        /// The direction of the transcript.
        direction: Direction,
    },
    /// The encoding provider is missing the encoding for the given range.
    #[error(
        "the encoding provider is missing the encoding for the given range: \
        {direction:?} {ranges:?}"
    )]
    MissingEncoding {
        /// The input ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
    },
    /// The encoding tree is missing the encoding for the given range.
    #[error(
        "the encoding tree is missing the encoding for the given range: \
        {direction:?} {ranges:?}"
    )]
    MissingLeaf {
        /// The input ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
    },
}

/// A leaf in the encoding tree.
pub(crate) struct EncodingLeaf {
    pub(crate) encoding: Vec<u8>,
    pub(crate) nonce: [u8; 16],
}

impl EncodingLeaf {
    pub(super) fn new(encoding: Vec<u8>, nonce: [u8; 16]) -> Self {
        Self { encoding, nonce }
    }
}

/// A merkle tree of transcript encodings.
#[derive(Serialize, Deserialize)]
pub struct EncodingTree {
    /// Merkle tree of the commitments.
    tree: MerkleTree,
    /// Nonces used to blind the hashes.
    nonces: Vec<[u8; 16]>,
    /// Mapping between the index of a leaf and the subsequence it
    /// corresponds to.
    seqs: BiMap<usize, SubsequenceIdx>,
}

opaque_debug::implement!(EncodingTree);

impl EncodingTree {
    /// Creates a new encoding tree.
    ///
    /// # Arguments
    ///
    /// * `alg` - The hash algorithm to use.
    /// * `seqs` - The subsequence indices to commit to.
    /// * `provider` - The encoding provider.
    /// * `transcript_length` - The length of the transcript.
    pub fn new<'seq>(
        alg: HashAlgorithm,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
        provider: &impl EncodingProvider,
        transcript_length: &TranscriptLength,
    ) -> Result<Self, EncodingTreeError> {
        let mut tree = Self {
            tree: MerkleTree::new(alg),
            nonces: Vec::new(),
            seqs: BiMap::new(),
        };

        for seq in seqs {
            let end = seq.ranges.end().ok_or(EncodingTreeError::EmptyRange)?;
            let len = match seq.direction {
                Direction::Sent => transcript_length.sent as usize,
                Direction::Received => transcript_length.received as usize,
            };

            if end > len {
                return Err(EncodingTreeError::OutOfBounds {
                    input_end: end,
                    transcript_length: len,
                    direction: seq.direction,
                });
            }

            let encoding = provider.provide_subsequence(seq).ok_or_else(|| {
                EncodingTreeError::MissingEncoding {
                    ranges: seq.ranges.clone(),
                    direction: seq.direction,
                }
            })?;

            tree.add_leaf(seq.clone(), encoding);
        }

        Ok(tree)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Returns the hash algorithm of the tree.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.tree.algorithm()
    }

    /// Generates a proof for the given subsequences.
    ///
    /// # Arguments
    ///
    /// * `transcript` - The transcript to prove against.
    /// * `seqs` - The subsequences to prove.
    pub fn proof<'seq>(
        &self,
        transcript: &Transcript,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
    ) -> Result<EncodingProof, EncodingTreeError> {
        let mut openings = HashMap::new();
        for seq in seqs {
            let idx =
                *self
                    .seqs
                    .get_by_right(&seq)
                    .ok_or_else(|| EncodingTreeError::MissingLeaf {
                        ranges: seq.ranges.clone(),
                        direction: seq.direction,
                    })?;

            let data =
                transcript
                    .get_subsequence(seq)
                    .ok_or_else(|| EncodingTreeError::OutOfBounds {
                        input_end: seq.ranges.end().unwrap_or_default(),
                        transcript_length: transcript.len_of_direction(seq.direction),
                        direction: seq.direction,
                    })?;
            let nonce = self.nonces[idx];

            openings.insert(
                idx,
                Opening {
                    seq: Subsequence {
                        idx: seq.clone(),
                        data,
                    },
                    nonce,
                },
            );
        }

        let mut indices = openings.keys().copied().collect::<Vec<_>>();
        indices.sort();
        let inclusion_proof = self.tree.proof(&indices);

        Ok(EncodingProof {
            inclusion_proof,
            openings,
        })
    }

    /// Returns whether the tree contains the given subsequence.
    pub fn contains(&self, seq: &SubsequenceIdx) -> bool {
        self.seqs.contains_right(seq)
    }

    pub(super) fn add_leaf(&mut self, seq: SubsequenceIdx, encoding: Vec<u8>) {
        if self.seqs.contains_right(&seq) {
            // The subsequence is already in the tree.
            return;
        }

        let nonce: [u8; 16] = rand::thread_rng().gen();
        let leaf = EncodingLeaf::new(encoding, nonce);

        self.tree.insert(&leaf);
        self.nonces.push(nonce);
        self.seqs.insert(self.seqs.len(), seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::EncodingCommitment,
        fixtures::{encoder_seed, encoding_provider},
    };
    use tlsn_data_fixtures::http::{request::POST_JSON, response::OK_JSON};

    fn new_tree<'seq>(
        transcript: &Transcript,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
    ) -> Result<EncodingTree, EncodingTreeError> {
        let provider = encoding_provider(transcript.sent(), transcript.received());
        let transcript_length = TranscriptLength {
            sent: transcript.sent().len() as u32,
            received: transcript.received().len() as u32,
        };
        EncodingTree::new(HashAlgorithm::Blake3, seqs, &provider, &transcript_length)
    }

    #[test]
    fn test_encoding_tree() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx {
            ranges: (0..POST_JSON.len()).into(),
            direction: Direction::Sent,
        };
        let seq_1 = SubsequenceIdx {
            ranges: (0..OK_JSON.len()).into(),
            direction: Direction::Received,
        };

        let tree = new_tree(&transcript, [&seq_0, &seq_1].into_iter()).unwrap();

        assert!(tree.contains(&seq_0));
        assert!(tree.contains(&seq_1));

        let proof = tree
            .proof(&transcript, [&seq_0, &seq_1].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof.verify(&transcript.length(), &commitment).unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_multiple_ranges() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx {
            ranges: (0..1).into(),
            direction: Direction::Sent,
        };
        let seq_1 = SubsequenceIdx {
            ranges: (1..POST_JSON.len()).into(),
            direction: Direction::Sent,
        };
        let seq_2 = SubsequenceIdx {
            ranges: (0..1).into(),
            direction: Direction::Received,
        };
        let seq_3 = SubsequenceIdx {
            ranges: (1..OK_JSON.len()).into(),
            direction: Direction::Received,
        };

        let tree = new_tree(&transcript, [&seq_0, &seq_1, &seq_2, &seq_3].into_iter()).unwrap();

        assert!(tree.contains(&seq_0));
        assert!(tree.contains(&seq_1));
        assert!(tree.contains(&seq_2));
        assert!(tree.contains(&seq_3));

        let proof = tree
            .proof(&transcript, [&seq_0, &seq_1, &seq_2, &seq_3].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof.verify(&transcript.length(), &commitment).unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_out_of_bounds() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx {
            ranges: (0..POST_JSON.len() + 1).into(),
            direction: Direction::Sent,
        };
        let seq_1 = SubsequenceIdx {
            ranges: (0..OK_JSON.len() + 1).into(),
            direction: Direction::Received,
        };

        let result = new_tree(&transcript, [&seq_0].into_iter()).unwrap_err();
        assert!(matches!(result, EncodingTreeError::OutOfBounds { .. }));

        let result = new_tree(&transcript, [&seq_1].into_iter()).unwrap_err();
        assert!(matches!(result, EncodingTreeError::OutOfBounds { .. }));
    }

    #[test]
    fn test_encoding_tree_missing_encoding() {
        let provider = encoding_provider(&[], &[]);
        let transcript_length = TranscriptLength {
            sent: 8,
            received: 8,
        };

        let result = EncodingTree::new(
            HashAlgorithm::Blake3,
            [SubsequenceIdx {
                ranges: (0..8).into(),
                direction: Direction::Sent,
            }]
            .iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));

        let result = EncodingTree::new(
            HashAlgorithm::Blake3,
            [SubsequenceIdx {
                ranges: (0..8).into(),
                direction: Direction::Received,
            }]
            .iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));
    }
}
