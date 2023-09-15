use crate::{
    commitment::{Commitment, CommitmentId},
    error::Error,
    merkle::{MerkleProof, MerkleRoot},
    SubstringsCommitmentSet,
};
use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "tracing")]
use tracing::instrument;

/// Inclusion proof for a [SubstringsCommitmentSet]
///
/// Contains a [proof](MerkleProof) that several [commitments](crate::SubstringsCommitment)
/// are part of a Merkle tree with a given [root](MerkleRoot).
#[derive(Serialize, Deserialize)]
pub struct InclusionProof {
    commitments: SubstringsCommitmentSet,
    merkle_proof: MerkleProof,
    merkle_tree_leaf_count: u32,
}

impl InclusionProof {
    /// Creates a new InclusionProof
    pub fn new(
        commitments: SubstringsCommitmentSet,
        merkle_proof: MerkleProof,
        merkle_tree_leaf_count: u32,
    ) -> Self {
        Self {
            commitments,
            merkle_proof,
            merkle_tree_leaf_count,
        }
    }

    /// Verifies this inclusion proof against the merkle root from the header. Returns a
    /// <merkle tree index, commitment> hashmap.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip(self), err))]
    pub fn verify(&self, root: &MerkleRoot) -> Result<HashMap<CommitmentId, Commitment>, Error> {
        // <merkle tree index, commitment> hashmap which will be returned
        let mut map: HashMap<CommitmentId, Commitment> = HashMap::new();

        // ids and leaves to verify
        let (ids, leaves): (Vec<usize>, Vec<Hash>) = self
            .commitments
            .iter()
            .map(|c| {
                let id = c.id();
                let leaf = match c.commitment() {
                    Commitment::Blake3(com) => *com.encoding_hash(),
                };
                map.insert(*id, c.commitment().clone());
                (id.into_inner() as usize, leaf)
            })
            .unzip();

        self.merkle_proof
            .verify(root, &ids, &leaves, self.merkle_tree_leaf_count as usize)?;

        Ok(map)
    }

    /// Validates `self` and all its nested types
    pub fn validate(&self) -> Result<(), Error> {
        self.commitments.validate()?;

        // each commitment's merkle_tree_idx must be valid
        for comm in self.commitments.iter() {
            if comm.id().into_inner() >= self.merkle_tree_leaf_count {
                return Err(Error::ValidationError);
            }
        }

        Ok(())
    }

    /// Returns the set of commitments to substrings
    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
