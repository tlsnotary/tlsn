use crate::{
    handshake_data::HandshakeData, merkle::MerkleTree, substrings_commitment::SubstringsCommitment,
    transcript::Transcript,
};
use serde::Serialize;

#[derive(Default, Serialize)]
pub struct SessionData {
    handshake_data: HandshakeData,
    transcript: Transcript,
    merkle_tree: MerkleTree,
    commitments: Vec<SubstringsCommitment>,
}

impl SessionData {
    pub fn new(
        handshake_data: HandshakeData,
        transcript: Transcript,
        merkle_tree: MerkleTree,
        commitments: Vec<SubstringsCommitment>,
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

    pub fn commitments(&self) -> &[SubstringsCommitment] {
        &self.commitments
    }
}
