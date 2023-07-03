//! Contains types which are used for messaging between prover and notary

use serde::{Deserialize, Serialize};

use crate::{merkle::MerkleRoot, signature::Signature, SessionHeader};

/// A wrapper type for different messages
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum TlsnMessage {
    TranscriptCommitmentRoot(MerkleRoot),
    SignedSessionHeader(SignedSessionHeader),
    SessionHeader(SessionHeader),
}

/// Wraps header and signature into a single message type
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct SignedSessionHeader {
    pub header: SessionHeader,
    pub signature: Signature,
}
