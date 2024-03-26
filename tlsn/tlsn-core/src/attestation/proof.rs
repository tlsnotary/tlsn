use serde::{Deserialize, Serialize};

use crate::{
    attestation::{AttestationBody, AttestationError, AttestationHeader},
    merkle::MerkleProof,
};

/// An attestation proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationProof {
    body: AttestationBody,
    proof: MerkleProof,
}

impl AttestationProof {
    /// Verifies the attestation proof against the attestation header.
    pub fn verify(self, header: &AttestationHeader) -> Result<AttestationBody, AttestationError> {
        let mut fields: Vec<_> = self
            .body
            .fields
            .iter()
            .map(|(id, field)| (id.0 as usize, field.clone()))
            .collect();
        fields.sort_by_key(|(id, _)| *id);
        let (leaf_indices, leafs): (Vec<_>, Vec<_>) = fields.into_iter().unzip();

        self.proof
            .verify(&header.root, &leaf_indices, &leafs)
            .unwrap();

        Ok(self.body)
    }
}
