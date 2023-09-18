//! Protocol message types.

use serde::{Deserialize, Serialize};

use crate::{merkle::MerkleRoot, signature::Signature, SessionHeader};

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
pub enum TlsnMessage {
    /// A Merkle root for the tree of commitments to the transcript.
    TranscriptCommitmentRoot(MerkleRoot),
    /// A session header signed by a notary.
    SignedSessionHeader(SignedSessionHeader),
    /// A session header.
    SessionHeader(SessionHeader),
}

/// A signed session header.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedSessionHeader {
    /// The session header
    pub header: SessionHeader,
    /// The notary's signature
    pub signature: Signature,
}
