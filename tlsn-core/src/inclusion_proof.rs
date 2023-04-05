use std::collections::HashMap;

use crate::{
    commitment::Commitment, error::Error, merkle::MerkleProof,
    substrings_commitment::SubstringsCommitment, SessionHeader,
};

pub struct InclusionProof {
    commitments: Vec<SubstringsCommitment>,
    merkle_proof: MerkleProof,
    merkle_tree_leaf_count: u32,
}

impl InclusionProof {
    pub fn new(
        commitments: Vec<SubstringsCommitment>,
        merkle_proof: MerkleProof,
        merkle_tree_leaf_count: u32,
    ) -> Self {
        Self {
            commitments,
            merkle_proof,
            merkle_tree_leaf_count,
        }
    }

    /// Verify against the merkle root from the header
    pub fn verify(&self, header: &SessionHeader) -> Result<HashMap<u32, Commitment>, Error> {
        // TODO check that all commitment indices are unique

        let mut map: HashMap<u32, Commitment> = HashMap::new();

        // indices and leaves to verify
        let (indices, leaves): (Vec<usize>, Vec<[u8; 32]>) = self
            .commitments
            .iter()
            .map(|c| {
                let idx = c.merkle_tree_index();
                let leaf = match c.commitment() {
                    Commitment::Blake3(com) => *com.labels_hash(),
                };
                map.insert(idx, c.commitment().clone());
                (idx as usize, leaf)
            })
            .unzip();

        if !self.merkle_proof.0.verify(
            *header.merkle_root(),
            &indices,
            &leaves,
            self.merkle_tree_leaf_count as usize,
        ) {
            return Err(Error::MerkleProofVerificationFailed);
        }

        Ok(map)
    }
}
