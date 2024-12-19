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

                // Insert the rangeset if it's in the encoding tree (which means it's a
                // committed rangeset).
                if encoding_tree.contains(&dir_idx) {
                    if !self.is_revealed(&dir_idx) && !self.is_subset_of_revealed(&dir_idx) {
                        self.encoding_proof_idxs.insert(dir_idx);
                    }
                } else {
                    let mut missing_commitment = true;
                    // Check if there is any committed rangeset in the encoding tree that is a
                    // subset of the rangeset — if yes, insert them.
                    for committed_dir_idx in encoding_tree
                        .transcript_indices()
                        .into_iter()
                        .filter(|(dir, _)| *dir == dir_idx.0)
                    {
                        // TODO: optimise is_subset to do boundary check first
                        if !self.is_revealed(&committed_dir_idx) && committed_dir_idx.1.is_subset(&dir_idx.1) && !self.is_subset_of_revealed(&committed_dir_idx) {
                            self.encoding_proof_idxs.insert(committed_dir_idx.clone());
                            missing_commitment = false; 
                        }
                    }
                    // If no committed rangeset is a subset, that means the rangeset is missing
                    // fully or partially in the encoding tree (which means it has not been
                    // committed).
                    if missing_commitment {
                        return Err(TranscriptProofBuilderError::new(
                            BuilderErrorKind::MissingCommitment,
                            format!(
                                "encoding commitment is missing for ranges in {} transcript",
                                direction
                            ),
                        ));
                    }
                }
            }
            TranscriptCommitmentKind::Hash { .. } => {
                let plaintext_hash_secrets =
                    // Get the secret if idx is in self.plaintext_hashes, i.e. it's committed.
                    if let Some(secret) = self.plaintext_hashes.get_by_transcript_idx(&idx) {
                        vec![secret]
                    } else {
                        // Collect any secret whose rangeset is a subset of idx.
                        self.plaintext_hashes
                            .iter()
                            .filter(|secret| secret.idx.is_subset(&idx))
                            .collect()
                    };
                if plaintext_hash_secrets.is_empty() {
                    return Err(TranscriptProofBuilderError::new(
                        BuilderErrorKind::MissingCommitment,
                        format!(
                            "hash commitment is missing for ranges in {} transcript",
                            direction
                        ),
                    ));
                }
                for secret in plaintext_hash_secrets.into_iter() {
                    let PlaintextHashSecret {
                        direction,
                        commitment,
                        blinder,
                        ..
                    } = secret;
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
        }
        Ok(self)
    }

    fn is_revealed(&self, dir_idx: &(Direction, Idx)) -> bool {
        self.encoding_proof_idxs.contains(&dir_idx)
    }

    fn is_subset_of_revealed(&self, dir_idx: &(Direction, Idx)) -> bool {
        let (dir , idx) = dir_idx;
        for (_, revealed_idx) in self.encoding_proof_idxs.iter().filter(|(revealed_dir, _)| revealed_dir == dir) {
            if idx.is_subset(revealed_idx) {
                return true;
            }
        }
        false
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
    use rstest::rstest;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};
    use utils::range::RangeSet;

    use crate::{
        attestation::FieldId,
        fixtures::{
            attestation_fixture, encoder_seed, encoding_provider, request_fixture,
            ConnectionFixture, RequestFixture,
        },
        hash::{Blake3, HashAlgId},
        signing::SignatureAlgId,
        transcript::TranscriptCommitConfigBuilder,
    };

    use super::*;

    #[rstest]
    fn test_reveal_range_out_of_bounds() {
        let transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &index);

        let err = builder.reveal(&(10..15), Direction::Sent).err().unwrap();
        assert!(matches!(err.kind, BuilderErrorKind::Index));

        let err = builder
            .reveal(&(10..15), Direction::Received)
            .err()
            .unwrap();
        assert!(matches!(err.kind, BuilderErrorKind::Index));
    }

    #[rstest]
    fn test_reveal_missing_encoding_tree() {
        let transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &index);

        let err = builder.reveal_recv(&(9..11)).err().unwrap();
        assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
    }

    #[rstest]
    fn test_reveal_missing_encoding_commitment_range() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { encoding_tree, .. } = request_fixture(
            transcript.clone(),
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection,
            Blake3::default(),
        );

        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, Some(&encoding_tree), &index);

        let err = builder.reveal_recv(&(0..11)).err().unwrap();
        assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
    }

    #[rstest]
    fn test_verify_missing_encoding_commitment() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture {
            mut request,
            encoding_tree,
        } = request_fixture(
            transcript.clone(),
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
        );

        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, Some(&encoding_tree), &index);

        builder.reveal_recv(&(0..transcript.len().1)).unwrap();

        let transcript_proof = builder.build().unwrap();

        request.encoding_commitment_root = None;
        let attestation = attestation_fixture(
            request,
            connection,
            SignatureAlgId::SECP256K1,
            encoder_seed().to_vec(),
        );

        let provider = CryptoProvider::default();
        let err = transcript_proof
            .verify_with_provider(&provider, &attestation.body)
            .err()
            .unwrap();
        assert!(matches!(err.kind, ErrorKind::Encoding));
    }

    #[rstest]
    #[case::multiple_reveal_ranges_all_committed_subset(
        vec![RangeSet::from([0..10]), RangeSet::from([12..30])],
        RangeSet::from([0..20, 20..30]),
        true,
    )]
    #[case::single_reveal_range_all_committed_subset(
        vec![RangeSet::from([0..20, 45..56]), RangeSet::from([80..100])],
        RangeSet::from([0..120]),
        true,
    )]
    #[case::multiple_reveal_ranges_some_committed_subset(
        vec![RangeSet::from([0..10]), RangeSet::from([15..40, 75..110])],
        RangeSet::from([0..41, 44..50, 74..100]),
        true,
    )]
    #[case::single_reveal_range_some_committed_subset(
        vec![RangeSet::from([2..50]), RangeSet::from([75..119])],
        RangeSet::from([33..120]),
        true,
    )]
    #[case::multiple_reveal_ranges_no_committed_subset(
        vec![RangeSet::from([5..15, 25..60]), RangeSet::from([79..100])],
        RangeSet::from([0..4, 15..40, 60..80]),
        false,
    )]
    #[case::single_reveal_range_no_committed_subset(
        vec![RangeSet::from([10..40, 99..105]), RangeSet::from([106..117])],
        RangeSet::from([100..103]),
        false,
    )]
    #[allow(clippy::single_range_in_vec_init)]
    fn test_reveal_mutliple_committed_rangesets_with_one_rangeset(
        #[case] commit_recv_rangesets: Vec<RangeSet<usize>>,
        #[case] reveal_recv_rangeset: RangeSet<usize>,
        #[case] success: bool,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        // Encoding commitment kind
        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        for rangeset in commit_recv_rangesets.iter() {
            transcript_commitment_builder.commit_recv(rangeset).unwrap();
        }

        let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

        let encoding_tree = EncodingTree::new(
            &Blake3::default(),
            transcripts_commitment_config.iter_encoding(),
            &encoding_provider(GET_WITH_HEADER, OK_JSON),
            &transcript.length(),
        )
        .unwrap();

        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, Some(&encoding_tree), &index);

        if success {
            assert!(builder.reveal_recv(&reveal_recv_rangeset).is_ok());
        } else {
            let err = builder.reveal_recv(&reveal_recv_rangeset).err().unwrap();
            assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
        }

        // Hash commitment kind
        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        });
        for rangeset in commit_recv_rangesets.iter() {
            transcript_commitment_builder.commit_recv(rangeset).unwrap();
        }
        let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

        let plaintext_hash_secrets: Index<PlaintextHashSecret> = transcripts_commitment_config
            .iter_hash()
            .map(|(&(direction, ref idx), _)| PlaintextHashSecret {
                direction,
                idx: idx.clone(),
                commitment: FieldId::default(),
                blinder: rand::random(),
            })
            .collect::<Vec<PlaintextHashSecret>>()
            .into();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &plaintext_hash_secrets);
        builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        });

        if success {
            assert!(builder.reveal_recv(&reveal_recv_rangeset).is_ok());
        } else {
            let err = builder.reveal_recv(&reveal_recv_rangeset).err().unwrap();
            assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
        }
    }
}
