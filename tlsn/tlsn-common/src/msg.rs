//! TLSNotary protocol messages.

use serde::{Deserialize, Serialize};
use tlsn_core::{
    attestation::{Attestation, AttestationHeader},
    conn::{Certificate, CertificateData, ServerIdentity, ServerSignature},
    substring::SubstringProofConfig,
    transcript::Subsequence,
    Signature,
};

use crate::attestation::{AttestationRequest, SignedAttestation};

/// TLSNotary protocol message.
#[derive(Debug, Serialize, Deserialize)]
pub enum TlsnMessage {
    /// Attestation request.
    AttestationRequest(AttestationRequest),
    /// Signed attestation.
    SignedAttestation(SignedAttestation),
    /// Server identity proof.
    ServerIdentityProof(ServerIdentityProof),
    /// Substring proof data.
    SubstringProofData(SubstringProofData),
}

/// Server identity proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerIdentityProof {
    /// Certificate data.
    pub cert_data: CertificateData,
    /// Server identity.
    pub identity: ServerIdentity,
}

/// Substring proof data.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubstringProofData {
    /// Subsequences.
    pub seqs: Vec<Subsequence>,
}
