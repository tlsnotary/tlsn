use crate::{pubkey::PubKey, HashCommitment};
use serde::{Deserialize, Serialize};

/// Handshake summary is part of the session header signed by the Notary
#[derive(Clone, Serialize, Deserialize)]
pub struct HandshakeSummary {
    /// time when Notary signed the session header
    // TODO: we can change this to be the time when the Notary started the TLS handshake 2PC
    time: u64,
    /// ephemeral pubkey for ECDH key exchange
    ephemeral_ec_pubkey: PubKey,
    /// User's commitment to [crate::handshake_data::HandshakeData]
    handshake_commitment: HashCommitment,
}

impl HandshakeSummary {
    pub fn new(
        time: u64,
        ephemeral_ec_pubkey: PubKey,
        handshake_commitment: HashCommitment,
    ) -> Self {
        Self {
            time,
            ephemeral_ec_pubkey,
            handshake_commitment,
        }
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn ephemeral_ec_pubkey(&self) -> &PubKey {
        &self.ephemeral_ec_pubkey
    }

    pub fn handshake_commitment(&self) -> &HashCommitment {
        &self.handshake_commitment
    }
}
