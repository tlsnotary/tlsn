//! Substring functionality.

mod config;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{AttestationBody, Field},
    encoding::EncodingProof,
    hash::{HashAlgorithm, PlaintextHashOpening},
    transcript::PartialTranscript,
};

pub use config::{
    SubstringCommitConfig, SubstringCommitConfigBuilder, SubstringCommitConfigBuilderError,
    SubstringProofConfig, SubstringProofConfigBuilder, SubstringProofConfigBuilderError,
};

/// Kind of transcript commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubstringCommitmentKind {
    /// A commitment to the encodings of the transcript.
    Encoding,
    /// A hash commitment to some plaintext in the transcript.
    Hash {
        /// The hash algorithm used.
        alg: HashAlgorithm,
    },
}

/// A proof of substrings in a transcript.
#[derive(Serialize, Deserialize)]
pub struct SubstringProof {
    pub(crate) encoding: Option<EncodingProof>,
    pub(crate) hash_openings: Vec<PlaintextHashOpening>,
}

opaque_debug::implement!(SubstringProof);

impl SubstringProof {
    /// Verifies the proof using the attestation body.
    ///
    /// Returns a partial transcript of authenticated data.
    ///
    /// # Arguments
    ///
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify(self, attestation_body: &AttestationBody) -> Result<PartialTranscript, ()> {
        let info = attestation_body.get_info().unwrap();

        let mut transcript = PartialTranscript::new(
            info.transcript_length.sent as usize,
            info.transcript_length.received as usize,
        );

        // Verify encoding proof.
        if let Some(proof) = self.encoding {
            let commitment = attestation_body.get_encoding_commitment().unwrap();

            transcript
                .union_transcript(&proof.verify(&info.transcript_length, commitment).unwrap());
        }

        // Verify hash openings.
        for opening in self.hash_openings {
            let Field::PlaintextHash(commitment) =
                attestation_body.get(opening.commitment_id()).unwrap()
            else {
                panic!();
            };

            let seq = opening.verify(commitment).unwrap();
            transcript.union_subsequence(&seq);
        }

        Ok(transcript)
    }
}
