use rs_merkle::{
    algorithms, algorithms::Sha256, proof_serializers, MerkleProof as MerkleProof_rs_merkle,
    MerkleTree as MerkleTree_rs_merkle,
};

use serde::{ser::Serializer, Serialize};

/// A wrapper around rs_merkle's MerkleProof with an added Clone impl
/// and serde serializer
#[derive(Serialize)]
pub struct MerkleProof(
    #[serde(serialize_with = "merkle_proof_serialize")]
    pub  MerkleProof_rs_merkle<algorithms::Sha256>,
);

impl Clone for MerkleProof {
    fn clone(&self) -> Self {
        let bytes = self.0.to_bytes();
        Self(MerkleProof_rs_merkle::<algorithms::Sha256>::from_bytes(&bytes).unwrap())
    }
}

/// A wrapper which impl Serialize
#[derive(Serialize, Default)]
pub struct MerkleTree(
    #[serde(serialize_with = "merkle_tree_serialize")] pub MerkleTree_rs_merkle<Sha256>,
);

/// Serialize the rs_merkle's MerkleProof type using its native `serialize` method
fn merkle_proof_serialize<S>(
    proof: &MerkleProof_rs_merkle<algorithms::Sha256>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = proof.serialize::<proof_serializers::DirectHashesOrder>();
    serializer.serialize_bytes(&bytes)
}

/// Serialize the rs_merkle's MerkleProof type using its native `serialize` method
fn merkle_tree_serialize<S>(
    tree: &MerkleTree_rs_merkle<algorithms::Sha256>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // TODO not implemented
    let bytes = [0u8; 32];
    serializer.serialize_bytes(&bytes)
}
