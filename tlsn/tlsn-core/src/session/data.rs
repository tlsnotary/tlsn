use crate::{merkle::MerkleTree, SubstringsCommitmentSet, Transcript};
use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

/// Wrapper for various data associated with the TLSNotary session
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    tx_transcript: Transcript,
    rx_transcript: Transcript,
    merkle_tree: MerkleTree,
    commitments: SubstringsCommitmentSet,
}

impl SessionData {
    /// Create a new instance of SessionData
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

    /// Getter for handshake_data_decommitment
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    /// Getter for tx_transcript
    pub fn sent_transcript(&self) -> &Transcript {
        &self.tx_transcript
    }

    /// Getter for rx_transcript
    pub fn recv_transcript(&self) -> &Transcript {
        &self.rx_transcript
    }

    /// Getter for merkle_tree
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// Getter for commitments
    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
