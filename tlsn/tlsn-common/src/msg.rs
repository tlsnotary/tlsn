//! TLSNotary protocol messages.

use serde::{Deserialize, Serialize};
use tlsn_core::{
    attestation::{Attestation, AttestationHeader},
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
}
