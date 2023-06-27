use crate::{merkle::MerkleTree, SubstringsCommitmentSet, Transcript};
use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    tx_transcript: Transcript,
    rx_transcript: Transcript,
    merkle_tree: MerkleTree,
    commitments: SubstringsCommitmentSet,
}

impl SessionData {
    pub fn new(
        handshake_data_decommitment: Decommitment<HandshakeData>,
        tx_transcript: Transcript,
        rx_transcript: Transcript,
        merkle_tree: MerkleTree,
        commitments: SubstringsCommitmentSet,
    ) -> Self {
        Self {
            handshake_data_decommitment,
            tx_transcript,
            rx_transcript,
            merkle_tree,
            commitments,
        }
    }

    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    pub fn sent_transcript(&self) -> &Transcript {
        &self.tx_transcript
    }

    pub fn recv_transcript(&self) -> &Transcript {
        &self.rx_transcript
    }

    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
