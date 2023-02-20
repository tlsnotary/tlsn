use rs_merkle::{algorithms, proof_serializers, MerkleProof as MerkleProof_rs_merkle};
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
