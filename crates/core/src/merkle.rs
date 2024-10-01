//! Merkle tree types.

use serde::{Deserialize, Serialize};
use utils::iter::DuplicateCheck;

use crate::hash::{Hash, HashAlgId, HashAlgorithm, TypedHash};

/// Errors that can occur during operations with Merkle tree and Merkle proof
#[derive(Debug, thiserror::Error)]
#[error("merkle error: {0}")]
pub(crate) struct MerkleError(String);

impl MerkleError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MerkleProof {
    alg: HashAlgId,
    tree_len: usize,
    proof: rs_merkle::MerkleProof<Hash>,
}

opaque_debug::implement!(MerkleProof);

impl MerkleProof {
    /// Checks if indices, hashes and leaves count are valid for the provided
    /// root
    ///
    /// # Panics
    ///
    /// - If the length of `leaf_indices` and `leaf_hashes` does not match.
    /// - If `leaf_indices` contains duplicates.
    pub(crate) fn verify(
        &self,
        hasher: &dyn HashAlgorithm,
        root: &TypedHash,
        leaves: impl IntoIterator<Item = (usize, Hash)>,
    ) -> Result<(), MerkleError> {
        let mut leaves = leaves.into_iter().collect::<Vec<_>>();

        // Sort by index
        leaves.sort_by_key(|(idx, _)| *idx);

        let (indices, leaves): (Vec<_>, Vec<_>) = leaves.into_iter().unzip();

        if indices.iter().contains_dups() {
            return Err(MerkleError::new("duplicate leaf indices provided"));
        }

        if !self.proof.verify(
            &RsMerkleHasher(hasher),
            root.value,
            &indices,
            &leaves,
            self.tree_len,
        ) {
            return Err(MerkleError::new("invalid merkle proof"));
        }

        Ok(())
    }
}

#[derive(Clone)]
struct RsMerkleHasher<'a>(&'a dyn HashAlgorithm);

impl rs_merkle::Hasher for RsMerkleHasher<'_> {
    type Hash = Hash;

    fn hash(&self, data: &[u8]) -> Hash {
        self.0.hash(data)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MerkleTree {
    alg: HashAlgId,
    tree: rs_merkle::MerkleTree<Hash>,
}

impl MerkleTree {
    pub(crate) fn new(alg: HashAlgId) -> Self {
        Self {
            alg,
            tree: Default::default(),
        }
    }

    pub(crate) fn algorithm(&self) -> HashAlgId {
        self.alg
    }

    pub(crate) fn root(&self) -> TypedHash {
        TypedHash {
            alg: self.alg,
            value: self.tree.root().expect("tree should not be empty"),
        }
    }

    /// Inserts leaves into the tree.
    ///
    /// # Panics
    ///
    /// - If the provided hasher is not the same as the one used to create the
    ///   tree.
    pub(crate) fn insert(&mut self, hasher: &dyn HashAlgorithm, mut leaves: Vec<Hash>) {
        assert_eq!(self.alg, hasher.id(), "hash algorithm mismatch");

        self.tree.append(&mut leaves);
        self.tree.commit(&RsMerkleHasher(hasher))
    }

    /// Returns a Merkle proof for the provided indices.
    ///
    /// # Panics
    ///
    /// - If the provided indices are not unique and sorted.
    pub(crate) fn proof(&self, indices: &[usize]) -> MerkleProof {
        assert!(
            indices.windows(2).all(|w| w[0] < w[1]),
            "indices must be unique and sorted"
        );

        MerkleProof {
            alg: self.alg,
            tree_len: self.tree.leaves_len(),
            proof: self.tree.proof(indices),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hash::{impl_domain_separator, Blake3, HashAlgorithmExt, Keccak256, Sha256};

    use super::*;
    use rstest::*;

    #[derive(Serialize)]
    struct T(u64);

    impl_domain_separator!(T);

    fn leaves<H: HashAlgorithm>(hasher: &H, leaves: impl IntoIterator<Item = T>) -> Vec<Hash> {
        leaves
            .into_iter()
            .map(|x| hasher.hash_canonical(&x))
            .collect()
    }

    fn choose_leaves(
        indices: impl IntoIterator<Item = usize>,
        leaves: &[Hash],
    ) -> Vec<(usize, Hash)> {
        indices.into_iter().map(|i| (i, leaves[i])).collect()
    }

    // Expect Merkle proof verification to succeed
    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_success<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let proof = tree.proof(&[2, 3, 4]);

        assert!(proof
            .verify(&hasher, &tree.root(), choose_leaves([2, 3, 4], &leaves))
            .is_ok());
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_fail_wrong_leaf<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let proof = tree.proof(&[2, 3, 4]);

        let mut choices = choose_leaves([2, 3, 4], &leaves);

        choices[1].1 = leaves[0];

        // fail because the leaf is wrong
        assert!(proof.verify(&hasher, &tree.root(), choices).is_err());
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    #[should_panic]
    fn test_proof_fail_length_unsorted<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        _ = tree.proof(&[2, 4, 3]);
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    #[should_panic]
    fn test_proof_fail_length_duplicates<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        _ = tree.proof(&[2, 2, 3]);
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_fail_duplicates<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let proof = tree.proof(&[2, 3, 4]);

        assert!(proof
            .verify(&hasher, &tree.root(), choose_leaves([2, 2, 3], &leaves))
            .is_err());
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_fail_incorrect_leaf_count<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let mut proof = tree.proof(&[2, 3, 4]);

        proof.tree_len += 1;

        // fail because leaf count is wrong
        assert!(proof
            .verify(&hasher, &tree.root(), choose_leaves([2, 3, 4], &leaves))
            .is_err());
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_fail_incorrect_indices<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let proof = tree.proof(&[2, 3, 4]);

        let mut choices = choose_leaves([2, 3, 4], &leaves);
        choices[1].0 = 1;

        // fail because leaf index is wrong
        assert!(proof.verify(&hasher, &tree.root(), choices).is_err());
    }

    #[rstest]
    #[case::sha2(Sha256::default())]
    #[case::blake3(Blake3::default())]
    #[case::keccak(Keccak256::default())]
    fn test_verify_fail_fewer_indices<H: HashAlgorithm>(#[case] hasher: H) {
        let mut tree = MerkleTree::new(hasher.id());

        let leaves = leaves(&hasher, [T(0), T(1), T(2), T(3), T(4)]);

        tree.insert(&hasher, leaves.clone());

        let proof = tree.proof(&[2, 3, 4]);

        // trying to verify less leaves than what was included in the proof
        assert!(proof
            .verify(&hasher, &tree.root(), choose_leaves([2, 3], &leaves))
            .is_err());
    }
}
