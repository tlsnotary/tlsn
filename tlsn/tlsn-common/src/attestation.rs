//! Attestation types.

use serde::{Deserialize, Serialize};
use tlsn_core::{
    attestation::AttestationHeader,
    hash::{Hash, HashAlgorithm},
    Signature,
};

/// Attestation request.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    /// Hash algorithm for the attestation.
    pub hash_alg: HashAlgorithm,
    /// The time the prover recorded starting the connection.
    pub time: u64,
    /// Certificate commitment.
    pub cert_commitment: Hash,
    /// Certificate chain commitment.
    pub cert_chain_commitment: Hash,
    /// Encoding commitment root.
    pub encoding_commitment_root: Option<Hash>,
    /// Extra data fields.
    pub extra_data: Vec<Vec<u8>>,
}

/// Signed attestation header.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// Signature of the attestation header.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
}
