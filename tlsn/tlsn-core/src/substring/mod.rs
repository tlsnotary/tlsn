mod config;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{AttestationBody, Field},
    encoding::EncodingProof,
    hash::{HashAlgorithm, PlaintextHashOpening},
    transcript::PartialTranscript,
    Direction,
};

pub use config::SubstringsCommitConfig;

/// Kind of transcript commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubstringCommitmentKind {
    /// A commitment to the encodings of the transcript.
    Encoding,
    /// A hash commitment to some plaintext in the transcript.
    Hash { alg: Option<HashAlgorithm> },
}

/// A proof of substrings in a transcript.
pub struct SubstringsProof {
    encoding: Option<EncodingProof>,
    hash_openings: Vec<PlaintextHashOpening>,
}

impl SubstringsProof {
    /// Verifies the proof using the attestation body.
    ///
    /// Returns the partial sent and received transcripts, respectively.
    ///
    /// # Arguments
    ///
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify(
        self,
        attestation_body: &AttestationBody,
    ) -> Result<(PartialTranscript, PartialTranscript), ()> {
        let info = attestation_body.get_info().unwrap();

        let mut sent = PartialTranscript::new(info.transcript_length.sent as usize);
        let mut recv = PartialTranscript::new(info.transcript_length.received as usize);

        // Verify encoding proof.
        if let Some(proof) = self.encoding {
            let commitment = attestation_body.get_encoding_commitment().unwrap();

            let (sent_, recv_) = proof.verify(&info.transcript_length, commitment).unwrap();
            sent.union(&sent_);
            recv.union(&recv_);
        }

        // Verify hash openings.
        for opening in self.hash_openings {
            let Field::PlaintextHash(commitment) =
                attestation_body.get(opening.commitment_id()).unwrap()
            else {
                panic!();
            };

            let seq = opening.verify(commitment).unwrap();
            match seq.idx.direction {
                Direction::Sent => {
                    sent.union_subsequence(&seq);
                }
                Direction::Received => {
                    recv.union_subsequence(&seq);
                }
            }
        }

        Ok((sent, recv))
    }
}
