//! Substring functionality.

mod config;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{AttestationBody, Field, FieldId, FieldKind},
    encoding::{EncodingProof, EncodingProofError},
    hash::{HashAlgorithm, PlaintextHashProof, PlaintextHashProofError},
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

/// An error for [`SubstringProof`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringProofError {
    /// Encoding proof error.
    #[error("encoding proof error: {0}")]
    Encoding(#[from] EncodingProofError),
    /// Hash proof error.
    #[error("hash proof error: {0}")]
    Hash(#[from] PlaintextHashProofError),
    /// Attestation is missing a required field.
    #[error("missing field: {0:?}")]
    MissingField(FieldKind),
    /// Incorrect field kind.
    #[error("incorrect field kind: {kind:?} expected for field {id:?}")]
    IncorrectField {
        /// The field id.
        id: FieldId,
        /// The expected field kind.
        kind: FieldKind,
    },
}

/// A proof of substrings in a transcript.
#[derive(Serialize, Deserialize)]
pub struct SubstringProof {
    pub(crate) encoding_proof: Option<EncodingProof>,
    pub(crate) hash_proofs: Vec<PlaintextHashProof>,
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
    pub(crate) fn verify(
        self,
        attestation_body: &AttestationBody,
    ) -> Result<PartialTranscript, SubstringProofError> {
        let info = attestation_body
            .get_info()
            .ok_or_else(|| SubstringProofError::MissingField(FieldKind::ConnectionInfo))?;

        let mut transcript = PartialTranscript::new(
            info.transcript_length.sent as usize,
            info.transcript_length.received as usize,
        );

        // Verify encoding proof.
        if let Some(proof) = self.encoding_proof {
            let commitment = attestation_body
                .get_encoding_commitment()
                .ok_or_else(|| SubstringProofError::MissingField(FieldKind::EncodingCommitment))?;
            let seq = proof.verify(&info.transcript_length, commitment)?;
            transcript.union_transcript(&seq);
        }

        // Verify hash openings.
        for opening in self.hash_proofs {
            let Field::PlaintextHash(commitment) = attestation_body
                .get(opening.commitment_id())
                .ok_or_else(|| SubstringProofError::MissingField(FieldKind::PlaintextHash))?
            else {
                return Err(SubstringProofError::IncorrectField {
                    id: opening.commitment_id().clone(),
                    kind: FieldKind::PlaintextHash,
                });
            };

            let seq = opening.verify(commitment)?;
            transcript.union_subsequence(&seq);
        }

        Ok(transcript)
    }
}
