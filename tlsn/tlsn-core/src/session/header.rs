use mpc_core::commit::Decommitment;
use serde::{Deserialize, Serialize};

use mpc_garble_core::ChaChaEncoder;
use tls_core::{handshake::HandshakeData, key::PublicKey};

use crate::{handshake_summary::HandshakeSummary, merkle::MerkleRoot, Error};

/// An authentic session header from the Notary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHeader {
    /// A PRG seeds used to generate encodings for the plaintext
    encoder_seed: [u8; 32],

    /// The root of the Merkle tree of all the commitments. The User must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the User to hide from the Notary the exact amount of commitments thus
    /// increasing User privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the User.
    merkle_root: MerkleRoot,

    /// Bytelength of all data which was sent to the webserver
    sent_len: u32,
    /// Bytelength of all data which was received from the webserver
    recv_len: u32,

    handshake_summary: HandshakeSummary,
}

impl SessionHeader {
    pub fn new(
        encoder_seed: [u8; 32],
        merkle_root: MerkleRoot,
        sent_len: u32,
        recv_len: u32,
        handshake_summary: HandshakeSummary,
    ) -> Self {
        Self {
            encoder_seed,
            merkle_root,
            sent_len,
            recv_len,
            handshake_summary,
        }
    }

    /// Verify the data in the header is consistent with the Prover's view
    pub fn verify(
        &self,
        time: u64,
        server_public_key: &PublicKey,
        root: &MerkleRoot,
        encoder_seed: &[u8; 32],
        handshake_data_decommitment: &Decommitment<HandshakeData>,
    ) -> Result<(), Error> {
        let ok_time = self.handshake_summary.time().abs_diff(time) <= 300;
        let ok_root = &self.merkle_root == root;
        let ok_encoder_seed = &self.encoder_seed == encoder_seed;
        let ok_handshake_data = handshake_data_decommitment
            .verify(self.handshake_summary.handshake_commitment())
            .is_ok();
        let ok_server_public_key = self.handshake_summary.server_public_key() == server_public_key;

        if !(ok_time && ok_root && ok_encoder_seed && ok_handshake_data && ok_server_public_key) {
            return Err(Error::WrongSessionHeader);
        }

        Ok(())
    }

    pub fn encoder(&self) -> ChaChaEncoder {
        ChaChaEncoder::new(self.encoder_seed)
    }

    pub fn label_seed(&self) -> &[u8; 32] {
        &self.encoder_seed
    }

    pub fn merkle_root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    pub fn handshake_summary(&self) -> &HandshakeSummary {
        &self.handshake_summary
    }

    pub fn sent_len(&self) -> u32 {
        self.sent_len
    }

    pub fn recv_len(&self) -> u32 {
        self.recv_len
    }
}
