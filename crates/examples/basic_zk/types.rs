use serde::{Deserialize, Serialize};
use tlsn::transcript::{hash::PlaintextHash, Direction, TranscriptCommitment};

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKProofBundle {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
}

// extract commitment from prover output
pub fn received_commitments(
    transcript_commitments: &[TranscriptCommitment],
) -> Vec<&PlaintextHash> {
    transcript_commitments
        .iter()
        .filter_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .collect()
}
