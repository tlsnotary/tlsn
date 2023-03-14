use crate::HashCommitment;
use serde::Serialize;

#[derive(Clone, Serialize, Default)]
pub struct HandshakeSummary {
    /// notarization time against which the TLS Certificate validity is checked
    time: u64,
    /// ephemeral pubkey for ECDH key exchange
    ephemeral_ec_pubkey: EphemeralECPubkey,
    /// User's commitment to [crate::handshake_data::HandshakeData]
    handshake_commitment: HashCommitment,
}

impl HandshakeSummary {
    pub fn new(
        time: u64,
        ephemeral_ec_pubkey: EphemeralECPubkey,
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

    pub fn ephemeral_ec_pubkey(&self) -> &EphemeralECPubkey {
        &self.ephemeral_ec_pubkey
    }

    pub fn handshake_commitment(&self) -> &HashCommitment {
        &self.handshake_commitment
    }
}

/// Types of the ephemeral EC pubkey currently supported by TLSNotary
#[derive(Clone, Serialize, Default)]
pub enum EphemeralECPubkeyType {
    #[default]
    P256,
}

/// The ephemeral EC public key (part of the TLS key exchange parameters)
#[derive(Clone, Serialize, Default)]
pub struct EphemeralECPubkey {
    typ: EphemeralECPubkeyType,
    pubkey: Vec<u8>,
}

impl EphemeralECPubkey {
    pub fn new(typ: EphemeralECPubkeyType, pubkey: Vec<u8>) -> Self {
        Self { typ, pubkey }
    }

    pub fn typ(&self) -> &EphemeralECPubkeyType {
        &self.typ
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }
}
