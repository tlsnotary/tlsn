use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};

use mpz_garble_core::ChaChaEncoder;
use tls_core::{handshake::HandshakeData, key::PublicKey};

use crate::{merkle::MerkleRoot, HandshakeSummary};

/// An error that can occur while verifying a session header
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionHeaderVerifyError {
    /// The session header is not consistent with the provided data
    #[error("session header is not consistent with the provided data")]
    InconsistentHeader,
}

/// An authentic session header from the Notary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHeader {
    /// A PRG seeds used to generate encodings for the plaintext
    encoder_seed: [u8; 32],

    /// The root of the Merkle tree of all the commitments. The Prover must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the Prover to hide from the Notary the exact amount of commitments thus
    /// increasing Prover privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the Prover.
    merkle_root: MerkleRoot,

    /// Bytelength of all data which was sent to the webserver
    sent_len: usize,
    /// Bytelength of all data which was received from the webserver
    recv_len: usize,

    handshake_summary: HandshakeSummary,
}

impl SessionHeader {
    /// Create a new instance of SessionHeader
    pub fn new(
        encoder_seed: [u8; 32],
        merkle_root: MerkleRoot,
        sent_len: usize,
        recv_len: usize,
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
    ) -> Result<(), SessionHeaderVerifyError> {
        let ok_time = self.handshake_summary.time().abs_diff(time) <= 300;
        let ok_root = &self.merkle_root == root;
        let ok_encoder_seed = &self.encoder_seed == encoder_seed;
        let ok_handshake_data = handshake_data_decommitment
            .verify(self.handshake_summary.handshake_commitment())
            .is_ok();
        let ok_server_public_key = self.handshake_summary.server_public_key() == server_public_key;

        if !(ok_time && ok_root && ok_encoder_seed && ok_handshake_data && ok_server_public_key) {
            return Err(SessionHeaderVerifyError::InconsistentHeader);
        }

        Ok(())
    }

    /// Create a new [ChaChaEncoder] from encoder_seed
    pub fn encoder(&self) -> ChaChaEncoder {
        ChaChaEncoder::new(self.encoder_seed)
    }

    /// Returns the seed used to generate plaintext encodings
    pub fn encoder_seed(&self) -> &[u8; 32] {
        &self.encoder_seed
    }

    /// Returns the merkle_root of the merkle tree of the prover's commitments
    pub fn merkle_root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    /// Returns the [HandshakeSummary] of the TLS session between prover and server
    pub fn handshake_summary(&self) -> &HandshakeSummary {
        &self.handshake_summary
    }

    /// Time of the TLS session, in seconds since the UNIX epoch.
    ///
    /// # Note
    ///
    /// This time is not necessarily exactly aligned with the TLS handshake.
    pub fn time(&self) -> u64 {
        self.handshake_summary.time()
    }

    /// Returns the number of bytes sent to the server
    pub fn sent_len(&self) -> usize {
        self.sent_len
    }

    /// Returns the number of bytes received by the server
    pub fn recv_len(&self) -> usize {
        self.recv_len
    }
}
