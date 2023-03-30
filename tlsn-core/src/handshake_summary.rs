use crate::{pubkey::PubKey, HashCommitment};
use serde::Serialize;

#[derive(Clone, Serialize, Default)]
pub struct HandshakeSummary {
    /// notarization time against which the TLS Certificate validity is checked
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

/// Types of the ephemeral EC pubkey currently supported by TLSNotary
#[derive(Clone, Serialize, Default)]
pub enum EphemeralKeyType {
    #[default]
    P256,
}

/// The ephemeral EC public key (part of the TLS key exchange parameters)
#[derive(Clone, Serialize, Default)]
pub struct EphemeralKey {
    typ: EphemeralKeyType,
    pubkey: Vec<u8>,
}

impl EphemeralKey {
    pub fn new(typ: EphemeralKeyType, pubkey: Vec<u8>) -> Self {
        Self { typ, pubkey }
    }

    pub fn typ(&self) -> &EphemeralKeyType {
        &self.typ
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }
}
