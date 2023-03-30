use crate::{merkle::MerkleTree, HandshakeData, SubstringsCommitmentSet, Transcript};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data: HandshakeData,
    transcript: Transcript,
    merkle_tree: MerkleTree,
    commitments: SubstringsCommitmentSet,
}

impl SessionData {
    pub fn new(
        handshake_data: HandshakeData,
        transcript: Transcript,
        merkle_tree: MerkleTree,
        commitments: SubstringsCommitmentSet,
    ) -> Self {
        Self {
            handshake_data,
            transcript,
            merkle_tree,
            commitments,
        }
    }

    pub fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
