//! Merkle tree types.
//!
//! # Usage
//!
//! During notarization, the `Prover` generates various commitments to the transcript data, which are subsequently
//! inserted into a `MerkleTree`. Rather than send each commitment to the Notary individually, the `Prover` simply sends the
//! `MerkleRoot`. This hides the number of commitments from the Notary, which is important for privacy as it can leak
//! information about the content of the transcript.
//!
//! Later, during selective disclosure to a `Verifier`, the `Prover` can open any subset of the commitments in the `MerkleTree`
//! by providing a `MerkleProof` for the corresponding `MerkleRoot` which was signed by the Notary.

use mpz_core::hash::Hash;
use rs_merkle::{
    algorithms::Sha256, proof_serializers, MerkleProof as MerkleProof_rs_merkle,
    MerkleTree as MerkleTree_rs_merkle,
};
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};
use utils::iter::DuplicateCheck;

/// A Merkle root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Returns the inner byte array
    pub fn to_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Errors that can occur during operations with Merkle tree and Merkle proof
#[derive(Debug, thiserror::Error, PartialEq)]
#[allow(missing_docs)]
pub enum MerkleError {
    #[error("Failed to verify a Merkle proof")]
    MerkleProofVerificationFailed,
    #[error("No leaves were provided when constructing a Merkle tree")]
    MerkleNoLeavesProvided,
}

/// A Merkle proof.
#[derive(Serialize, Deserialize)]
pub struct MerkleProof {
    #[serde(
        serialize_with = "merkle_proof_serialize",
        deserialize_with = "merkle_proof_deserialize"
    )]
    proof: MerkleProof_rs_merkle<Sha256>,
    total_leaves: usize,
}

impl MerkleProof {
    /// Checks if indices, hashes and leaves count are valid for the provided root
    ///
    /// # Panics
    ///
    /// - If the length of `leaf_indices` and `leaf_hashes` does not match.
    /// - If `leaf_indices` contains duplicates.
    pub fn verify(
        &self,
        root: &MerkleRoot,
        leaf_indices: &[usize],
        leaf_hashes: &[Hash],
    ) -> Result<(), MerkleError> {
        assert_eq!(
            leaf_indices.len(),
            leaf_hashes.len(),
            "leaf indices length must match leaf hashes length"
        );
        assert!(
            !leaf_indices.iter().contains_dups(),
            "duplicate indices provided {:?}",
            leaf_indices
        );

        // zip indices and hashes
        let mut tuples: Vec<(usize, [u8; 32])> = leaf_indices
            .iter()
            .cloned()
            .zip(leaf_hashes.iter().cloned().map(|h| *h.as_bytes()))
            .collect();

        // sort by index and unzip
        tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        let (indices, hashes): (Vec<usize>, Vec<[u8; 32]>) = tuples.into_iter().unzip();

        if !self
            .proof
            .verify(root.to_inner(), &indices, &hashes, self.total_leaves)
        {
            return Err(MerkleError::MerkleProofVerificationFailed);
        }
        Ok(())
    }
}

impl Clone for MerkleProof {
    fn clone(&self) -> Self {
        let bytes = self.proof.to_bytes();
        Self {
            proof: MerkleProof_rs_merkle::<Sha256>::from_bytes(&bytes).unwrap(),
            total_leaves: self.total_leaves,
        }
    }
}

fn merkle_proof_serialize<S>(
    proof: &MerkleProof_rs_merkle<Sha256>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = proof.serialize::<proof_serializers::DirectHashesOrder>();
    serializer.serialize_bytes(&bytes)
}

fn merkle_proof_deserialize<'de, D>(
    deserializer: D,
) -> Result<MerkleProof_rs_merkle<Sha256>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::deserialize(deserializer)?;
    MerkleProof_rs_merkle::<Sha256>::from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
}

/// A Merkle tree.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct MerkleTree(
    #[serde(
        serialize_with = "merkle_tree_serialize",
        deserialize_with = "merkle_tree_deserialize"
    )]
    pub MerkleTree_rs_merkle<Sha256>,
);

impl MerkleTree {
    /// Create a new Merkle tree from the given `leaves`
    pub fn from_leaves(leaves: &[Hash]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::MerkleNoLeavesProvided);
        }
        let leaves: Vec<[u8; 32]> = leaves.iter().map(|h| *h.as_bytes()).collect();
        Ok(Self(MerkleTree_rs_merkle::<Sha256>::from_leaves(&leaves)))
    }

    /// Creates an inclusion proof for the given `indices`
    ///
    /// # Panics
    ///
    /// - if `indices` is not sorted.
    /// - if `indices` contains duplicates
    pub fn proof(&self, indices: &[usize]) -> MerkleProof {
        assert!(
            indices.windows(2).all(|w| w[0] < w[1]),
            "indices must be sorted"
        );

        let proof = self.0.proof(indices);
        MerkleProof {
            proof,
            total_leaves: self.0.leaves_len(),
        }
    }

    /// Returns the Merkle root for this MerkleTree
    pub fn root(&self) -> MerkleRoot {
        self.0
            .root()
            .expect("Merkle root should be available")
            .into()
    }
}

/// Serialize the rs_merkle's `MerkleTree` type
fn merkle_tree_serialize<S>(
    tree: &MerkleTree_rs_merkle<Sha256>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // all leaves are sha256 hashes
    let hash_size = 32;
    let mut bytes: Vec<u8> = Vec::with_capacity(tree.leaves_len() * hash_size);
    if let Some(leaves) = tree.leaves() {
        for leaf in leaves {
            bytes.append(&mut leaf.to_vec());
        }
    }

    serializer.serialize_bytes(&bytes)
}

fn merkle_tree_deserialize<'de, D>(
    deserializer: D,
) -> Result<MerkleTree_rs_merkle<Sha256>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    if bytes.len() % 32 != 0 {
        return Err(serde::de::Error::custom("leaves must be 32 bytes"));
    }
    let leaves: Vec<[u8; 32]> = bytes.chunks(32).map(|c| c.try_into().unwrap()).collect();

    Ok(MerkleTree_rs_merkle::<Sha256>::from_leaves(
        leaves.as_slice(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    // Expect Merkle proof verification to succeed
    #[test]
    fn test_verify_success() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        assert!(proof
            .verify(&tree.root(), &[2, 3, 4], &[leaf2, leaf3, leaf4])
            .is_ok(),);
    }

    #[test]
    fn test_verify_fail_wrong_leaf() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        // fail because the leaf is wrong
        assert_eq!(
            proof
                .verify(&tree.root(), &[2, 3, 4], &[leaf1, leaf3, leaf4])
                .err()
                .unwrap(),
            MerkleError::MerkleProofVerificationFailed
        );
    }

    #[test]
    #[should_panic]
    fn test_proof_fail_length_unsorted() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        _ = tree.proof(&[2, 4, 3]);
    }

    #[test]
    #[should_panic]
    fn test_proof_fail_length_duplicates() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        _ = tree.proof(&[2, 2, 3]);
    }

    #[test]
    #[should_panic]
    fn test_verify_fail_length_mismatch() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        _ = proof.verify(&tree.root(), &[1, 2, 3, 4], &[leaf2, leaf3, leaf4]);
    }

    #[test]
    #[should_panic]
    fn test_verify_fail_duplicates() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        _ = proof.verify(&tree.root(), &[2, 2, 3], &[leaf2, leaf2, leaf3]);
    }

    #[test]
    fn test_verify_fail_incorrect_leaf_count() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let mut proof = tree.proof(&[2, 3, 4]);

        proof.total_leaves = 6;

        // fail because leaf count is wrong
        assert!(proof
            .verify(&tree.root(), &[2, 3, 4], &[leaf2, leaf3, leaf4])
            .is_err());
    }

    #[test]
    fn test_verify_fail_incorrect_indices() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        // fail because tree index is wrong
        assert!(proof
            .verify(&tree.root(), &[1, 3, 4], &[leaf1, leaf3, leaf4])
            .is_err());
    }

    #[test]
    fn test_verify_fail_fewer_indices() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        // trying to verify less leaves than what was included in the proof
        assert!(proof
            .verify(&tree.root(), &[3, 4], &[leaf3, leaf4])
            .is_err());
    }

    // Expect MerkleProof/MerkleTree custom serialization/deserialization to work
    #[test]
    fn test_serialization() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]).unwrap();
        let proof = tree.proof(&[2, 3, 4]);

        // serialize
        let tree_bytes = bincode::serialize(&tree).unwrap();
        let proof_bytes = bincode::serialize(&proof).unwrap();

        // deserialize
        let tree2: MerkleTree = bincode::deserialize(&tree_bytes).unwrap();
        let proof2: MerkleProof = bincode::deserialize(&proof_bytes).unwrap();

        assert!(proof2
            .verify(&tree2.root(), &[2, 3, 4], &[leaf2, leaf3, leaf4])
            .is_ok());
    }
}
