use std::collections::HashMap;

use bimap::BiMap;
use serde::{Deserialize, Serialize};

use crate::{
    connection::TranscriptLength,
    hash::{Blinder, HashAlgId, HashAlgorithm, TypedHash},
    merkle::MerkleTree,
    transcript::{
        encoding::{
            proof::{EncodingProof, Opening},
            EncodingProvider,
        },
        Direction, Idx,
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

/// A merkle tree of transcript encodings.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncodingTree {
    /// Merkle tree of the commitments.
    tree: MerkleTree,
    /// Nonces used to blind the hashes.
    blinders: Vec<Blinder>,
    /// Mapping between the index of a leaf and the transcript index it
    /// corresponds to.
    idxs: BiMap<usize, (Direction, Idx)>,
    /// Union of all transcript indices in the sent direction.
    sent_idx: Idx,
    /// Union of all transcript indices in the received direction.
    received_idx: Idx,
}

opaque_debug::implement!(EncodingTree);

impl EncodingTree {
    /// Creates a new encoding tree.
    ///
    /// # Arguments
    ///
    /// * `hasher` - The hash algorithm to use.
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
            blinders: Vec::new(),
            idxs: BiMap::new(),
            sent_idx: Idx::empty(),
            received_idx: Idx::empty(),
        };

        let mut leaves = Vec::new();
        let mut encoding = Vec::new();
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

            let blinder: Blinder = rand::random();

            encoding.clear();
            for range in idx.iter_ranges() {
                provider
                    .provide_encoding(direction, range, &mut encoding)
                    .map_err(|_| EncodingTreeError::MissingEncoding { index: idx.clone() })?;
            }
            encoding.extend_from_slice(blinder.as_bytes());

            let leaf = hasher.hash(&encoding);

            leaves.push(leaf);
            this.blinders.push(blinder);
            this.idxs.insert(this.idxs.len(), dir_idx.clone());
            match direction {
                Direction::Sent => this.sent_idx.union_mut(idx),
                Direction::Received => this.received_idx.union_mut(idx),
            }
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
    /// * `idxs` - The transcript indices to prove.
    pub fn proof<'idx>(
        &self,
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
            let blinder = self.blinders[leaf_idx].clone();

            openings.insert(
                leaf_idx,
                Opening {
                    direction,
                    idx: idx.clone(),
                    blinder,
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

    pub(crate) fn idx(&self, direction: Direction) -> &Idx {
        match direction {
            Direction::Sent => &self.sent_idx,
            Direction::Received => &self.received_idx,
        }
    }

    /// Returns the committed transcript indices.
    pub(crate) fn transcript_indices(&self) -> impl Iterator<Item = &(Direction, Idx)> {
        self.idxs.right_values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{encoder_secret, encoding_provider},
        hash::Blake3,
        transcript::{encoding::EncodingCommitment, Transcript},
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

        let proof = tree.proof([&idx_0, &idx_1].into_iter()).unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            secret: encoder_secret(),
        };

        let (auth_sent, auth_recv) = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &commitment,
                transcript.sent(),
                transcript.received(),
            )
            .unwrap();

        assert_eq!(auth_sent, idx_0.1);
        assert_eq!(auth_recv, idx_1.1);
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
            .proof([&idx_0, &idx_1, &idx_2, &idx_3].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            secret: encoder_secret(),
        };

        let (auth_sent, auth_recv) = proof
            .verify_with_provider(
                &CryptoProvider::default(),
                &commitment,
                transcript.sent(),
                transcript.received(),
            )
            .unwrap();

        let mut expected_auth_sent = Idx::default();
        expected_auth_sent.union_mut(&idx_0.1);
        expected_auth_sent.union_mut(&idx_1.1);

        let mut expected_auth_recv = Idx::default();
        expected_auth_recv.union_mut(&idx_2.1);
        expected_auth_recv.union_mut(&idx_3.1);

        assert_eq!(auth_sent, expected_auth_sent);
        assert_eq!(auth_recv, expected_auth_recv);
    }

    #[test]
    fn test_encoding_tree_proof_missing_leaf() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let idx_0 = (Direction::Sent, Idx::new(0..POST_JSON.len()));
        let idx_1 = (Direction::Received, Idx::new(0..4));
        let idx_2 = (Direction::Received, Idx::new(4..OK_JSON.len()));

        let tree = new_tree(&transcript, [&idx_0, &idx_1].into_iter()).unwrap();

        let result = tree
            .proof([&idx_0, &idx_1, &idx_2].into_iter())
            .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingLeaf { .. }));
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
    }
}
