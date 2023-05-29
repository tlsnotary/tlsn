use serde::{Deserialize, Serialize};

use crate::{merkle::MerkleRoot, signature::Signature, SessionHeader};

#[derive(Debug, Serialize, Deserialize)]
pub enum TlsnMessage {
    TranscriptCommitmentRoot(MerkleRoot),
    SignedSessionHeader(SignedSessionHeader),
    SessionHeader(SessionHeader),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedSessionHeader {
    pub header: SessionHeader,
    pub signature: Signature,
}
