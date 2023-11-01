//! Protocol message types.

use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    merkle::MerkleRoot,
    proof::{substring::LabelProof, SessionInfo},
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
    /// The label for the sent transcript
    pub sent_label: String,
    /// The ids for the send transcript from which to reconstruct the value refs
    pub sent_ids: RangeSet<usize>,

    /// The label for the sent transcript
    pub recv_label: String,
    /// The ids for the received transcript from which to reconstruct the value refs
    pub recv_ids: RangeSet<usize>,
}

impl From<LabelProof> for DecodingInfo {
    fn from(value: LabelProof) -> Self {
        Self {
            sent_label: value.sent_label,
            sent_ids: value.sent_ids,

            recv_label: value.recv_label,
            recv_ids: value.recv_ids,
        }
    }
}
