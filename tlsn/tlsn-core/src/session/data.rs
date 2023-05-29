use crate::{merkle::MerkleTree, transcript::TranscriptSet, SubstringsCommitmentSet, Transcript};
use mpc_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    transcripts: TranscriptSet,
    merkle_tree: MerkleTree,
    commitments: SubstringsCommitmentSet,
}

impl SessionData {
    pub fn new(
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
        merkle_tree: MerkleTree,
        commitments: SubstringsCommitmentSet,
    ) -> Self {
        Self {
            handshake_data_decommitment,
            transcripts: TranscriptSet::new(&[transcript_tx, transcript_rx]),
            merkle_tree,
            commitments,
        }
    }

    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    pub fn transcripts(&self) -> &TranscriptSet {
        &self.transcripts
    }

    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
