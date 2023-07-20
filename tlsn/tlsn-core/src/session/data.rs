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

    /// Returns the decommitment to handshake data
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    /// Returns the transcript for data sent to the server
    pub fn sent_transcript(&self) -> &Transcript {
        &self.tx_transcript
    }

    /// Returns the transcript for data received from the server
    pub fn recv_transcript(&self) -> &Transcript {
        &self.rx_transcript
    }

    /// Returns the merkle tree for the prover's commitments
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// The prover's commitments to substrings of the transcript
    pub fn commitments(&self) -> &SubstringsCommitmentSet {
        &self.commitments
    }
}
