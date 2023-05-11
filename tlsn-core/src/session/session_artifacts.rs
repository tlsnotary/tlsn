use mpc_core::commit::Decommitment;

use crate::{merkle::MerkleTree, pubkey::PubKey, HandshakeData};

// Various artifacts which the User holds at the end of the notarization session
pub struct SessionArtifacts {
    // time when TLS handshake was initiated
    time: u64,
    // A Merkle tree of all the User's commitments
    merkle_tree: MerkleTree,
    // encoder seed revealed by the Notary at the end of the label commitment protocol
    encoder_seed: [u8; 32],
    // server ephemeral key
    ephem_key: PubKey,
    // decommitment to handshake data
    handshake_data_decommitment: Decommitment<HandshakeData>,
}

impl SessionArtifacts {
    pub fn new(
        time: u64,
        merkle_tree: MerkleTree,
        encoder_seed: [u8; 32],
        ephem_key: PubKey,
        handshake_data_decommitment: Decommitment<HandshakeData>,
    ) -> Self {
        Self {
            time,
            merkle_tree,
            encoder_seed,
            ephem_key,
            handshake_data_decommitment,
        }
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    pub fn encoder_seed(&self) -> &[u8; 32] {
        &self.encoder_seed
    }

    pub fn ephem_key(&self) -> &PubKey {
        &self.ephem_key
    }

    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }
}
