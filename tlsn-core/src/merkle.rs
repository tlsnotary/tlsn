use crate::error::Error;
use mpc_core::hash::Hash;
use rs_merkle::{
    algorithms::Sha256, proof_serializers, MerkleProof as MerkleProof_rs_merkle,
    MerkleTree as MerkleTree_rs_merkle,
};
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};
use utils::iter::DuplicateCheck;

pub type MerkleRoot = [u8; 32];

/// A wrapper for rs_merkle's `MerkleProof` which implements `Clone`
/// and a serializer/deserializer
#[derive(Serialize, Deserialize)]
pub struct MerkleProof(
    #[serde(
        serialize_with = "merkle_proof_serialize",
        deserialize_with = "merkle_proof_deserialize"
    )]
    MerkleProof_rs_merkle<Sha256>,
);

impl MerkleProof {
    pub fn verify(
        &self,
        root: &MerkleRoot,
        leaf_indices: &[usize],
        leaf_hashes: &[Hash],
        total_leaves_count: usize,
    ) -> Result<(), Error> {
        if leaf_indices.len() != leaf_hashes.len() {
            return Err(Error::MerkleProofVerificationFailed);
        }
        if leaf_indices.iter().contains_dups() {
            return Err(Error::MerkleProofVerificationFailed);
        }

        // zip indices and hashes
        let mut tuples: Vec<(usize, [u8; 32])> = leaf_indices
            .iter()
            .cloned()
            .zip(leaf_hashes.iter().cloned().map(|h| *h.as_bytes()))
            .collect();

        // sort by index and unzip
        tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        let (indices, hashes): (Vec<usize>, Vec<[u8; 32]>) = tuples.into_iter().unzip();

        if !self.0.verify(*root, &indices, &hashes, total_leaves_count) {
            return Err(Error::MerkleProofVerificationFailed);
        }
        Ok(())
    }
}

impl Clone for MerkleProof {
    fn clone(&self) -> Self {
        let bytes = self.0.to_bytes();
        Self(MerkleProof_rs_merkle::<Sha256>::from_bytes(&bytes).unwrap())
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

/// A wrapper for rs_merkle's `MerkleTree` which implements serializer/deserializer
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct MerkleTree(
    #[serde(
        serialize_with = "merkle_tree_serialize",
        deserialize_with = "merkle_tree_deserialize"
    )]
    pub MerkleTree_rs_merkle<Sha256>,
);

impl MerkleTree {
    /// Creates an inclusion proof for the given `indices`
    pub fn proof(&self, indices: &[usize]) -> MerkleProof {
        let proof = self.0.proof(indices);
        MerkleProof(proof)
    }

    pub fn from_leaves(leaves: &[Hash]) -> Self {
        let leaves: Vec<[u8; 32]> = leaves.iter().map(|h| *h.as_bytes()).collect();
        Self(MerkleTree_rs_merkle::<Sha256>::from_leaves(&leaves))
    }

    /// Returns the Merkle root for this MerkleTree
    pub fn root(&self) -> Result<MerkleRoot, Error> {
        match self.0.root() {
            Some(root) => Ok(root),
            _ => Err(Error::InternalError),
        }
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
pub mod test {
    use super::*;

    // Expect Merkle proof verification to succeed
    #[test]
    fn test_verify_success() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        assert!(proof
            .verify(&tree.root().unwrap(), &[2, 4, 3], &[leaf2, leaf4, leaf3], 5)
            .is_ok(),);
    }

    // Expect Merkle proof verification to fail
    #[test]
    fn test_verify_fail() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        // fail because the leaf is wrong
        assert!(
            proof
                .verify(&tree.root().unwrap(), &[2, 4, 3], &[leaf1, leaf4, leaf3], 5)
                .err()
                .unwrap()
                == Error::MerkleProofVerificationFailed
        );

        // fail because of the extra leaf which was not covered by the proof
        assert!(
            proof
                .verify(
                    &tree.root().unwrap(),
                    &[2, 4, 3, 0],
                    &[leaf2, leaf4, leaf3, leaf0],
                    5
                )
                .err()
                .unwrap()
                == Error::MerkleProofVerificationFailed
        );

        // fail because of leaf and index count mismatch
        assert!(
            proof
                .verify(
                    &tree.root().unwrap(),
                    &[1, 2, 4, 3],
                    &[leaf2, leaf4, leaf3],
                    5
                )
                .err()
                .unwrap()
                == Error::MerkleProofVerificationFailed
        );

        // fail because of duplicate leaf indices
        assert!(
            proof
                .verify(&tree.root().unwrap(), &[2, 2, 3], &[leaf2, leaf4, leaf3], 5)
                .err()
                .unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    // Expect MerkleProof/MerkleTree custom serialization/deserialization to work
    #[test]
    fn test_serialization() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        // serialize
        let tree_bytes = bincode::serialize(&tree).unwrap();
        let proof_bytes = bincode::serialize(&proof).unwrap();

        // deserialize
        let tree2: MerkleTree = bincode::deserialize(&tree_bytes).unwrap();
        let proof2: MerkleProof = bincode::deserialize(&proof_bytes).unwrap();

        assert!(proof2
            .verify(
                &tree2.root().unwrap(),
                &[2, 4, 3],
                &[leaf2, leaf4, leaf3],
                5
            )
            .is_ok(),);
    }

    // This test causes rs_merkle to panic
    #[ignore = "waiting for a panic in rs_merkle to be fixed"]
    #[test]
    fn test_verify_fail_panic1() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        // fail because tree index is wrong
        proof.verify(&tree.root().unwrap(), &[1, 4, 3], &[leaf2, leaf4, leaf3], 5);
    }

    // This test causes rs_merkle to panic
    // https://github.com/antouhou/rs-merkle/issues/20
    #[ignore = "waiting for a panic in rs_merkle to be fixed"]
    #[test]
    fn test_verify_fail_panic2() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        // fail because leaf count is wrong
        proof.verify(&tree.root().unwrap(), &[2, 4, 3], &[leaf2, leaf4, leaf3], 6);
    }

    // This test causes rs_merkle to panic
    #[ignore = "waiting for a panic in rs_merkle to be fixed"]
    #[test]
    fn test_verify_fail_panic3() {
        let leaf0 = Hash::from([0u8; 32]);
        let leaf1 = Hash::from([1u8; 32]);
        let leaf2 = Hash::from([2u8; 32]);
        let leaf3 = Hash::from([3u8; 32]);
        let leaf4 = Hash::from([4u8; 32]);
        let tree = MerkleTree::from_leaves(&[leaf0, leaf1, leaf2, leaf3, leaf4]);
        let proof = tree.proof(&[4, 2, 3]);

        // trying to verify less leaves than what was included in the proof
        proof.verify(&tree.root().unwrap(), &[4, 3], &[leaf4, leaf3], 5);
    }
}
