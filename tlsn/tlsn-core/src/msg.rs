//! Protocol message types.

use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    merkle::MerkleRoot,
    proof::{substring::TranscriptProof, SessionInfo},
    signature::Signature,
    SessionHeader,
};

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
pub enum TlsnMessage {
    /// A Merkle root for the tree of commitments to the transcript.
    TranscriptCommitmentRoot(MerkleRoot),
    /// A session header signed by a notary.
    SignedSessionHeader(SignedSessionHeader),
    /// A session header.
    SessionHeader(SessionHeader),
    /// Information about the TLS session
    SessionInfo(SessionInfo),
    /// Information about what values the prover wants to decode
    DecodingInfo(DecodingInfo),
}

/// A signed session header.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedSessionHeader {
    /// The session header
    pub header: SessionHeader,
    /// The notary's signature
    pub signature: Signature,
}

/// Information about what values the prover wants to decode
#[derive(Debug, Serialize, Deserialize)]
pub struct DecodingInfo {
    /// The ids for the send transcript from which to reconstruct the value refs
    pub sent_ids: RangeSet<usize>,
    /// The ids for the received transcript from which to reconstruct the value refs
    pub recv_ids: RangeSet<usize>,
}

impl From<TranscriptProof> for DecodingInfo {
    fn from(value: TranscriptProof) -> Self {
        Self {
            sent_ids: value.sent,
            recv_ids: value.recv,
        }
    }
}
