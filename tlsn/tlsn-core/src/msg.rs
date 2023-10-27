//! Protocol message types.

use serde::{Deserialize, Serialize};

use crate::{
    merkle::MerkleRoot,
    proof::{substring::LabelProof, TlsInfo},
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
    TlsInfo(TlsInfo),
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
    /// The ids from which to reconstruct the value refs
    pub ids: Vec<String>,
}

impl From<LabelProof> for DecodingInfo {
    fn from(value: LabelProof) -> Self {
        Self {
            ids: value
                .sent_ids()
                .iter()
                .chain(value.recv_ids())
                .cloned()
                .collect(),
        }
    }
}
