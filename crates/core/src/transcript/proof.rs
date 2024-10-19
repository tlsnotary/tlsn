//! Transcript proofs.

use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};
use utils::range::ToRangeSet;

use crate::{
    attestation::Body,
    hash::Blinded,
    index::Index,
    transcript::{
        commit::TranscriptCommitmentKind,
        encoding::{EncodingProof, EncodingProofError, EncodingTree},
        hash::{PlaintextHashProof, PlaintextHashProofError, PlaintextHashSecret},
        Direction, Idx, PartialTranscript, Transcript,
    },
    CryptoProvider,
};

/// Proof of the contents of a transcript.
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptProof {
    encoding_proof: Option<EncodingProof>,
    hash_proofs: Vec<PlaintextHashProof>,
}

opaque_debug::implement!(TranscriptProof);

impl TranscriptProof {
    /// Verifies the proof.
    ///
    /// Returns a partial transcript of authenticated data.
    ///
    /// # Arguments
    ///
    /// * `provider` - The crypto provider to use for verification.
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        attestation_body: &Body,
    ) -> Result<PartialTranscript, TranscriptProofError> {
        let info = attestation_body.connection_info();

        let mut transcript = PartialTranscript::new(
            info.transcript_length.sent as usize,
            info.transcript_length.received as usize,
        );

        // Verify encoding proof.
        if let Some(proof) = self.encoding_proof {
            let commitment = attestation_body.encoding_commitment().ok_or_else(|| {
                TranscriptProofError::new(
                    ErrorKind::Encoding,
                    "contains an encoding proof but attestation is missing encoding commitment",
                )
            })?;
            let seq = proof.verify_with_provider(provider, &info.transcript_length, commitment)?;
            transcript.union_transcript(&seq);
        }

        // Verify hash openings.
        for proof in self.hash_proofs {
            let commitment = attestation_body
                .plaintext_hashes()
                .get_by_field_id(proof.commitment_id())
                .map(|field| &field.data)
                .ok_or_else(|| {
                    TranscriptProofError::new(
                        ErrorKind::Hash,
                        format!("contains a hash opening but attestation is missing corresponding commitment (id: {})", proof.commitment_id()),
                    )
                })?;

            let (direction, seq) = proof.verify(&provider.hash, commitment)?;
            transcript.union_subsequence(direction, &seq);
        }

        Ok(transcript)
    }
}

/// Error for [`TranscriptProof`].
#[derive(Debug, thiserror::Error)]
pub struct TranscriptProofError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TranscriptProofError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Encoding,
    Hash,
}

impl fmt::Display for TranscriptProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("transcript proof error: ")?;

        match self.kind {
            ErrorKind::Encoding => f.write_str("encoding error")?,
            ErrorKind::Hash => f.write_str("hash error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<EncodingProofError> for TranscriptProofError {
    fn from(e: EncodingProofError) -> Self {
        TranscriptProofError::new(ErrorKind::Encoding, e)
    }
}

impl From<PlaintextHashProofError> for TranscriptProofError {
    fn from(e: PlaintextHashProofError) -> Self {
        TranscriptProofError::new(ErrorKind::Hash, e)
    }
}

/// Builder for [`TranscriptProof`].
#[derive(Debug)]
pub struct TranscriptProofBuilder<'a> {
    default_kind: TranscriptCommitmentKind,
    transcript: &'a Transcript,
    encoding_tree: Option<&'a EncodingTree>,
    plaintext_hashes: &'a Index<PlaintextHashSecret>,
    encoding_proof_idxs: HashSet<(Direction, Idx)>,
    hash_proofs: Vec<PlaintextHashProof>,
}

impl<'a> TranscriptProofBuilder<'a> {
    /// Creates a new proof config builder.
    pub(crate) fn new(
        transcript: &'a Transcript,
        encoding_tree: Option<&'a EncodingTree>,
        plaintext_hashes: &'a Index<PlaintextHashSecret>,
    ) -> Self {
        Self {
            default_kind: TranscriptCommitmentKind::Encoding,
            transcript,
            encoding_tree,
            plaintext_hashes,
            encoding_proof_idxs: HashSet::default(),
            hash_proofs: Vec::new(),
        }
    }

    /// Sets the default kind of commitment to open when revealing ranges.
    pub fn default_kind(&mut self, kind: TranscriptCommitmentKind) -> &mut Self {
        self.default_kind = kind;
        self
    }

    /// Reveals the given ranges in the transcript using the provided kind of
    /// commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    /// * `direction` - The direction of the transcript.
    /// * `kind` - The kind of commitment to open.
    pub fn reveal_with_kind(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
        kind: TranscriptCommitmentKind,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        let idx = Idx::new(ranges.to_range_set());

        if idx.end() > self.transcript.len_of_direction(direction) {
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::Index,
                format!(
                    "range is out of bounds of the transcript ({}): {} > {}",
                    direction,
                    idx.end(),
                    self.transcript.len_of_direction(direction)
                ),
            ));
        }

        match kind {
            TranscriptCommitmentKind::Encoding => {
                let Some(encoding_tree) = self.encoding_tree else {
                    return Err(TranscriptProofBuilderError::new(
                        BuilderErrorKind::MissingCommitment,
                        "encoding tree is missing",
                    ));
                };

                let dir_idx = (direction, idx);

                if !encoding_tree.contains(&dir_idx) {
                    return Err(TranscriptProofBuilderError::new(
                        BuilderErrorKind::MissingCommitment,
                        format!(
                            "encoding commitment is missing for ranges in {} transcript",
                            direction
                        ),
                    ));
                }

                self.encoding_proof_idxs.insert(dir_idx);
            }
            TranscriptCommitmentKind::Hash { .. } => {
                let Some(PlaintextHashSecret {
                    direction,
                    commitment,
                    blinder,
                    ..
                }) = self.plaintext_hashes.get_by_transcript_idx(&idx)
                else {
                    return Err(TranscriptProofBuilderError::new(
                        BuilderErrorKind::MissingCommitment,
                        format!(
                            "hash commitment is missing for ranges in {} transcript",
                            direction
                        ),
                    ));
                };

                let (_, data) = self
                    .transcript
                    .get(*direction, &idx)
                    .expect("subsequence was checked to be in transcript")
                    .into_parts();

                self.hash_proofs.push(PlaintextHashProof::new(
                    Blinded::new_with_blinder(data, blinder.clone()),
                    *commitment,
                ));
            }
        }

        Ok(self)
    }

    /// Reveals the given ranges in the transcript using the default kind of
    /// commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    /// * `direction` - The direction of the transcript.
    pub fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        self.reveal_with_kind(ranges, direction, self.default_kind)
    }

    /// Reveals the given ranges in the sent transcript using the default kind
    /// of commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        self.reveal(ranges, Direction::Sent)
    }

    /// Reveals the given ranges in the received transcript using the default
    /// kind of commitment.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        self.reveal(ranges, Direction::Received)
    }

    /// Builds the transcript proof.
    pub fn build(self) -> Result<TranscriptProof, TranscriptProofBuilderError> {
        let encoding_proof = if !self.encoding_proof_idxs.is_empty() {
            let encoding_tree = self.encoding_tree.expect("encoding tree is present");
            let proof = encoding_tree
                .proof(self.transcript, self.encoding_proof_idxs.iter())
                .expect("subsequences were checked to be in tree");
            Some(proof)
        } else {
            None
        };

        Ok(TranscriptProof {
            encoding_proof,
            hash_proofs: self.hash_proofs,
        })
    }
}

/// Error for [`TranscriptProofBuilder`].
#[derive(Debug, thiserror::Error)]
pub struct TranscriptProofBuilderError {
    kind: BuilderErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TranscriptProofBuilderError {
    fn new<E>(kind: BuilderErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum BuilderErrorKind {
    Index,
    MissingCommitment,
}

impl fmt::Display for TranscriptProofBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transcript proof builder error: ")?;

        match self.kind {
            BuilderErrorKind::Index => f.write_str("index error")?,
            BuilderErrorKind::MissingCommitment => f.write_str("commitment error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_out_of_bounds() {
        let transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &index);

        assert!(builder.reveal(&(10..15), Direction::Sent).is_err());
        assert!(builder.reveal(&(10..15), Direction::Received).is_err());
    }
}
