use std::collections::HashMap;

use bimap::BiMap;
use serde::{Deserialize, Serialize};

use crate::{
    connection::TranscriptLength,
    hash::{Blinded, Blinder, HashAlgId, HashAlgorithm, TypedHash},
    merkle::MerkleTree,
    serialize::CanonicalSerialize,
    transcript::{
        encoding::{
            proof::{EncodingProof, Opening},
            EncodingProvider,
        },
        Direction, Idx, Transcript,
    },
};

/// Encoding tree builder error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingTreeError {
    /// Index is out of bounds of the transcript.
    #[error("index is out of bounds of the transcript")]
    OutOfBounds {
        /// The index.
        index: Idx,
        /// The transcript length.
        transcript_length: usize,
    },
    /// Encoding provider is missing an encoding for an index.
    #[error("encoding provider is missing an encoding for an index")]
    MissingEncoding {
        /// The index which is missing.
        index: Idx,
    },
    /// Index is missing from the tree.
    #[error("index is missing from the tree")]
    MissingLeaf {
        /// The index which is missing.
        index: Idx,
    },
}

#[derive(Serialize)]
pub(crate) struct EncodingLeaf(Vec<u8>);

impl EncodingLeaf {
    pub(super) fn new(encoding: Vec<u8>) -> Self {
        Self(encoding)
    }
}

/// A merkle tree of transcript encodings.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncodingTree {
    /// Merkle tree of the commitments.
    tree: MerkleTree,
    /// Nonces used to blind the hashes.
    nonces: Vec<Blinder>,
    /// Mapping between the index of a leaf and the transcript index it
    /// corresponds to.
    idxs: BiMap<usize, (Direction, Idx)>,
}

opaque_debug::implement!(EncodingTree);

impl EncodingTree {
    /// Creates a new encoding tree.
    ///
    /// # Arguments
    ///
    /// * `alg` - The hash algorithm to use.
    /// * `idxs` - The subsequence indices to commit to.
    /// * `provider` - The encoding provider.
    /// * `transcript_length` - The length of the transcript.
    pub fn new<'idx>(
        hasher: &dyn HashAlgorithm,
        idxs: impl IntoIterator<Item = &'idx (Direction, Idx)>,
        provider: &dyn EncodingProvider,
        transcript_length: &TranscriptLength,
    ) -> Result<Self, EncodingTreeError> {
        let mut this = Self {
            tree: MerkleTree::new(hasher.id()),
            nonces: Vec::new(),
            idxs: BiMap::new(),
        };

        let mut leaves = Vec::new();
        for dir_idx in idxs {
            let direction = dir_idx.0;
            let idx = &dir_idx.1;

            // Ignore empty indices.
            if idx.is_empty() {
                continue;
            }

            let len = match direction {
                Direction::Sent => transcript_length.sent as usize,
                Direction::Received => transcript_length.received as usize,
            };

            if idx.end() > len {
                return Err(EncodingTreeError::OutOfBounds {
                    index: idx.clone(),
                    transcript_length: len,
                });
            }

            if this.idxs.contains_right(dir_idx) {
                // The subsequence is already in the tree.
                continue;
            }

            let encoding = provider
                .provide_encoding(direction, idx)
                .ok_or_else(|| EncodingTreeError::MissingEncoding { index: idx.clone() })?;

            let leaf = Blinded::new(EncodingLeaf::new(encoding));

            leaves.push(hasher.hash(&CanonicalSerialize::serialize(&leaf)));
            this.nonces.push(leaf.into_parts().1);
            this.idxs.insert(this.idxs.len(), dir_idx.clone());
        }

        this.tree.insert(hasher, leaves);

        Ok(this)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> TypedHash {
        self.tree.root()
    }

    /// Returns the hash algorithm of the tree.
    pub fn algorithm(&self) -> HashAlgId {
        self.tree.algorithm()
    }

    /// Generates a proof for the given indices.
    ///
    /// # Arguments
    ///
    /// * `transcript` - The transcript to prove against.
    /// * `idxs` - The transcript indices to prove.
    pub fn proof<'idx>(
        &self,
        transcript: &Transcript,
        idxs: impl Iterator<Item = &'idx (Direction, Idx)>,
    ) -> Result<EncodingProof, EncodingTreeError> {
        let mut openings = HashMap::new();
        for dir_idx in idxs {
            let direction = dir_idx.0;
            let idx = &dir_idx.1;

            let leaf_idx = *self
                .idxs
                .get_by_right(dir_idx)
                .ok_or_else(|| EncodingTreeError::MissingLeaf { index: idx.clone() })?;

            let seq =
                transcript
                    .get(direction, idx)
                    .ok_or_else(|| EncodingTreeError::OutOfBounds {
                        index: idx.clone(),
                        transcript_length: transcript.len_of_direction(direction),
                    })?;
            let nonce = self.nonces[leaf_idx].clone();

            openings.insert(
                leaf_idx,
                Opening {
                    direction,
                    seq,
                    blinder: nonce,
                },
            );
        }

        let mut indices = openings.keys().copied().collect::<Vec<_>>();
        indices.sort();

        Ok(EncodingProof {
            inclusion_proof: self.tree.proof(&indices),
            openings,
        })
    }

    /// Returns whether the tree contains the given transcript index.
    pub fn contains(&self, idx: &(Direction, Idx)) -> bool {
        self.idxs.contains_right(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{encoder_seed, encoding_provider},
        hash::Blake3,
        transcript::encoding::EncodingCommitment,
        CryptoProvider,
    };
    use tlsn_data_fixtures::http::{request::POST_JSON, response::OK_JSON};

    fn new_tree<'seq>(
        transcript: &Transcript,
        idxs: impl Iterator<Item = &'seq (Direction, Idx)>,
    ) -> Result<EncodingTree, EncodingTreeError> {
        let provider = encoding_provider(transcript.sent(), transcript.received());
        let transcript_length = TranscriptLength {
            sent: transcript.sent().len() as u32,
            received: transcript.received().len() as u32,
        };
        EncodingTree::new(&Blake3::default(), idxs, &provider, &transcript_length)
    }

    #[test]
    fn test_encoding_tree() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let idx_0 = (Direction::Sent, Idx::new(0..POST_JSON.len()));
        let idx_1 = (Direction::Received, Idx::new(0..OK_JSON.len()));

        let tree = new_tree(&transcript, [&idx_0, &idx_1].into_iter()).unwrap();

        assert!(tree.contains(&idx_0));
        assert!(tree.contains(&idx_1));

        let proof = tree
            .proof(&transcript, [&idx_0, &idx_1].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &transcript.length(),
                &commitment,
            )
            .unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_multiple_ranges() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let idx_0 = (Direction::Sent, Idx::new(0..1));
        let idx_1 = (Direction::Sent, Idx::new(1..POST_JSON.len()));
        let idx_2 = (Direction::Received, Idx::new(0..1));
        let idx_3 = (Direction::Received, Idx::new(1..OK_JSON.len()));

        let tree = new_tree(&transcript, [&idx_0, &idx_1, &idx_2, &idx_3].into_iter()).unwrap();

        assert!(tree.contains(&idx_0));
        assert!(tree.contains(&idx_1));
        assert!(tree.contains(&idx_2));
        assert!(tree.contains(&idx_3));

        let proof = tree
            .proof(&transcript, [&idx_0, &idx_1, &idx_2, &idx_3].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &transcript.length(),
                &commitment,
            )
            .unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_out_of_bounds() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let idx_0 = (Direction::Sent, Idx::new(0..POST_JSON.len() + 1));
        let idx_1 = (Direction::Received, Idx::new(0..OK_JSON.len() + 1));

        let result = new_tree(&transcript, [&idx_0].into_iter()).unwrap_err();
        assert!(matches!(result, EncodingTreeError::OutOfBounds { .. }));

        let result = new_tree(&transcript, [&idx_1].into_iter()).unwrap_err();
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
            &Blake3::default(),
            [(Direction::Sent, Idx::new(0..8))].iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));

        let result = EncodingTree::new(
            &Blake3::default(),
            [(Direction::Sent, Idx::new(0..8))].iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));
    }
}
