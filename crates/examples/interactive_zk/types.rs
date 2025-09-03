use serde::{Deserialize, Serialize};
use tlsn::transcript::{hash::PlaintextHash, Direction, TranscriptCommitment};

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKProofBundle {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub check_date: String,
}

// extract commitment from prover output
pub fn received_commitments(transcript_commitments: &[TranscriptCommitment]) -> Vec<PlaintextHash> {
    transcript_commitments
        .iter()
        .filter(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash.direction == Direction::Received
            } else {
                false
            }
        })
        .map(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash.clone()
            } else {
                unreachable!()
            }
        })
        .collect()
}
