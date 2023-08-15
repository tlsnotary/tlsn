//! Contains types which are used for messaging between prover and notary

use serde::{Deserialize, Serialize};

use crate::{merkle::MerkleRoot, signature::Signature, SessionHeader};

/// A wrapper type for different messages
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum TlsnMessage {
    /// Contains the merkle root of the merkle tree of the commitments to transcripts
    TranscriptCommitmentRoot(MerkleRoot),
    /// Contains the session header signed by the notary
    SignedSessionHeader(SignedSessionHeader),
    /// Contains the session header
    SessionHeader(SessionHeader),
}

/// Wraps header and signature into a single message type
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedSessionHeader {
    /// The session header
    pub header: SessionHeader,
    /// The notary's signature
    pub signature: Signature,
}
