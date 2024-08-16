//! Protocol message types.

use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{merkle::MerkleRoot, proof::SessionInfo, signature::Signature, SessionHeader};

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
pub enum TlsnMessage {
    /// A Merkle root for the tree of commitments to the transcript.
    TranscriptCommitmentRoot(MerkleRoot),
    /// A session header signed by a notary.
    SignedSessionHeader(SignedSessionHeader),
    /// A signature on application data
    SignedSession(SignedSession),
    /// A session header.
    SessionHeader(SessionHeader),
    /// Information about the TLS session
    SessionInfo(SessionInfo),
    /// Information about the values the prover wants to prove
    ProvingInfo(ProvingInfo),
}

/// A signed session header.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedSessionHeader {
    /// The session header
    pub header: SessionHeader,
    /// The notary's signature
    pub signature: Signature,
}

/// A signed session.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignedSession {
    /// The TLS application data
    pub application_data: String,
    /// The signature on application data
    pub signature: Signature,
}

opaque_debug::implement!(SignedSession);

impl SignedSession {
    /// Create a new notarized session.
    pub fn new(application_data: String, signature: Signature) -> Self {
        Self {
            application_data,
            signature,
        }
    }
}

/// Information about the values the prover wants to prove
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProvingInfo {
    /// The ids for the sent transcript
    pub sent_ids: RangeSet<usize>,
    /// The ids for the received transcript
    pub recv_ids: RangeSet<usize>,
    /// Purported cleartext values
    pub cleartext: Vec<u8>,
}
