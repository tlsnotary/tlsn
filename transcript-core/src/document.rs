use crate::{
    commitment::{Commitment, CommitmentOpening},
    merkle::MerkleProof,
    tls_handshake::TLSHandshake,
    LabelSeed,
};
use serde::Serialize;

/// Notarization document. This is the form in which the document is received
/// by the Verifier from the User.
#[derive(Serialize, Clone)]
pub struct Document {
    version: u8,
    tls_handshake: TLSHandshake,
    /// Notary's signature over the [crate::signed::Signed] portion of this doc
    signature: Option<Vec<u8>>,

    /// A PRG seeds from which to generate garbled circuit active labels, see
    /// [crate::commitment::CommitmentType::labels_blake3]
    label_seed: LabelSeed,

    /// The root of the Merkle tree of all the commitments. The User must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the User to hide from the Notary the exact amount of commitments thus
    /// increasing User privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the User.
    merkle_root: [u8; 32],

    /// The total leaf count in the Merkle tree of commitments. Provided by the User to the Verifier
    /// to enable merkle proof verification.
    merkle_tree_leaf_count: u32,

    /// A proof that all [commitments] are the leaves of the Merkle tree
    merkle_multi_proof: MerkleProof,

    /// User's commitments to various portions of the notarized data, sorted ascendingly by id
    commitments: Vec<Commitment>,

    /// Openings for the commitments, sorted ascendingly by id
    commitment_openings: Vec<CommitmentOpening>,
}

impl Document {
    /// Creates a new document
    pub fn new(
        version: u8,
        tls_handshake: TLSHandshake,
        signature: Option<Vec<u8>>,
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        merkle_tree_leaf_count: u32,
        merkle_multi_proof: MerkleProof,
        commitments: Vec<Commitment>,
        commitment_openings: Vec<CommitmentOpening>,
    ) -> Self {
        Self {
            version,
            tls_handshake,
            signature,
            label_seed,
            merkle_root,
            merkle_tree_leaf_count,
            merkle_multi_proof,
            commitments,
            commitment_openings,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn tls_handshake(&self) -> &TLSHandshake {
        &self.tls_handshake
    }

    pub fn signature(&self) -> &Option<Vec<u8>> {
        &self.signature
    }

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }

    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    pub fn merkle_tree_leaf_count(&self) -> u32 {
        self.merkle_tree_leaf_count
    }

    pub fn merkle_multi_proof(&self) -> &MerkleProof {
        &self.merkle_multi_proof
    }

    pub fn commitments(&self) -> &Vec<Commitment> {
        &self.commitments
    }

    pub fn commitment_openings(&self) -> &Vec<CommitmentOpening> {
        &self.commitment_openings
    }
}
