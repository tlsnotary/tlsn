//! Transcript proofs.

use rangeset::{Cover, ToRangeSet};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

use crate::{
    attestation::Body,
    index::Index,
    transcript::{
        commit::{TranscriptCommitmentKind, MAX_TOTAL_COMMITTED_DATA},
        encoding::{EncodingProof, EncodingProofError, EncodingTree},
        hash::{PlaintextHashProof, PlaintextHashProofError, PlaintextHashSecret},
        Direction, Idx, PartialTranscript, Transcript,
    },
    CryptoProvider,
};

/// Default commitment kinds in order of preference for building transcript
/// proofs.
const DEFAULT_COMMITMENT_KINDS: &[TranscriptCommitmentKind] = &[TranscriptCommitmentKind::Encoding];

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
        let mut total_opened = 0u128;

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

            // Make sure the amount of data being proved is bounded.
            total_opened += commitment.idx.len() as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(TranscriptProofError::new(
                    ErrorKind::Hash,
                    "exceeded maximum allowed data",
                ))?;
            }

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

/// Union of committed ranges of all commitment kinds.
#[derive(Debug)]
struct CommittedIdx {
    sent: Idx,
    recv: Idx,
}

impl CommittedIdx {
    fn new(
        encoding_tree: Option<&EncodingTree>,
        plaintext_hashes: &Index<PlaintextHashSecret>,
    ) -> Self {
        let mut sent = plaintext_hashes.idx(Direction::Sent).clone();
        let mut recv = plaintext_hashes.idx(Direction::Received).clone();

        if let Some(tree) = encoding_tree {
            sent.union_mut(tree.idx(Direction::Sent));
            recv.union_mut(tree.idx(Direction::Received));
        }

        Self { sent, recv }
    }

    fn idx(&self, direction: &Direction) -> &Idx {
        match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        }
    }
}

/// Union of ranges to reveal.
#[derive(Clone, Debug, PartialEq)]
struct QueryIdx {
    sent: Idx,
    recv: Idx,
}

impl QueryIdx {
    fn new() -> Self {
        Self {
            sent: Idx::empty(),
            recv: Idx::empty(),
        }
    }

    fn is_empty(&self) -> bool {
        self.sent.is_empty() && self.recv.is_empty()
    }

    fn union(&mut self, direction: &Direction, other: &Idx) {
        match direction {
            Direction::Sent => self.sent.union_mut(other),
            Direction::Received => self.recv.union_mut(other),
        }
    }
}

impl std::fmt::Display for QueryIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sent: {}, received: {}", self.sent, self.recv)
    }
}

/// Builder for [`TranscriptProof`].
#[derive(Debug)]
pub struct TranscriptProofBuilder<'a> {
    /// Commitment kinds in order of preference for building transcript proofs.
    commitment_kinds: Vec<TranscriptCommitmentKind>,
    transcript: &'a Transcript,
    encoding_tree: Option<&'a EncodingTree>,
    #[allow(dead_code)]
    plaintext_hashes: &'a Index<PlaintextHashSecret>,
    committed_idx: CommittedIdx,
    query_idx: QueryIdx,
}

impl<'a> TranscriptProofBuilder<'a> {
    /// Creates a new proof config builder.
    pub(crate) fn new(
        transcript: &'a Transcript,
        encoding_tree: Option<&'a EncodingTree>,
        plaintext_hashes: &'a Index<PlaintextHashSecret>,
    ) -> Self {
        Self {
            commitment_kinds: DEFAULT_COMMITMENT_KINDS.to_vec(),
            transcript,
            encoding_tree,
            plaintext_hashes,
            committed_idx: CommittedIdx::new(encoding_tree, plaintext_hashes),
            query_idx: QueryIdx::new(),
        }
    }

    /// Sets the commitment kinds in order of preference for building transcript
    /// proofs, i.e. the first one is the most preferred.
    pub fn commitment_kinds(&mut self, kinds: &[TranscriptCommitmentKind]) -> &mut Self {
        if !kinds.is_empty() {
            // Removes duplicates from `kinds` while preserving its order.
            let mut seen = HashSet::new();
            self.commitment_kinds = kinds
                .iter()
                .filter(|&kind| seen.insert(kind))
                .cloned()
                .collect();
        }
        self
    }

    /// Reveals the given ranges in the transcript.
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

        if idx.is_subset(self.committed_idx.idx(&direction)) {
            self.query_idx.union(&direction, &idx);
        } else {
            let missing = idx.difference(self.committed_idx.idx(&direction));
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::MissingCommitment,
                format!("commitment is missing for ranges in {direction} transcript: {missing}"),
            ));
        }
        Ok(self)
    }

    /// Reveals the given ranges in the sent transcript.
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

    /// Reveals the given ranges in the received transcript.
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
        let mut transcript_proof = TranscriptProof {
            encoding_proof: None,
            hash_proofs: Vec::new(),
        };
        let mut uncovered_query_idx = self.query_idx.clone();
        let mut commitment_kinds_iter = self.commitment_kinds.iter();

        // Tries to cover the query ranges with committed ranges.
        while !uncovered_query_idx.is_empty() {
            // Committed ranges of different kinds are checked in order of preference set in
            // self.commitment_kinds.
            if let Some(kind) = commitment_kinds_iter.next() {
                match kind {
                    TranscriptCommitmentKind::Encoding => {
                        let Some(encoding_tree) = self.encoding_tree else {
                            // Proceeds to the next preferred commitment kind if encoding tree is
                            // not available.
                            continue;
                        };

                        let (sent_dir_idxs, sent_uncovered) =
                            uncovered_query_idx.sent.as_range_set().cover_by(
                                encoding_tree
                                    .transcript_indices()
                                    .filter(|(dir, _)| *dir == Direction::Sent),
                                |(_, idx)| &idx.0,
                            );
                        // Uncovered ranges will be checked with ranges of the next
                        // preferred commitment kind.
                        uncovered_query_idx.sent = Idx(sent_uncovered);

                        let (recv_dir_idxs, recv_uncovered) =
                            uncovered_query_idx.recv.as_range_set().cover_by(
                                encoding_tree
                                    .transcript_indices()
                                    .filter(|(dir, _)| *dir == Direction::Received),
                                |(_, idx)| &idx.0,
                            );
                        uncovered_query_idx.recv = Idx(recv_uncovered);

                        let dir_idxs = sent_dir_idxs
                            .into_iter()
                            .chain(recv_dir_idxs)
                            .collect::<Vec<_>>();

                        // Skip proof generation if there are no committed ranges that can cover the
                        // query ranges.
                        if !dir_idxs.is_empty() {
                            transcript_proof.encoding_proof = Some(
                                encoding_tree
                                    .proof(self.transcript, dir_idxs.into_iter())
                                    .expect("subsequences were checked to be in tree"),
                            );
                        }
                    }
                    kind => {
                        return Err(TranscriptProofBuilderError::new(
                            BuilderErrorKind::NotSupported,
                            format!("opening {kind} transcript commitments is not yet supported"),
                        ));
                    }
                }
            } else {
                // Stops the set cover check if there are no more commitment kinds left.
                break;
            }
        }

        // If there are still uncovered ranges, it means that query ranges cannot be
        // covered by committed ranges of any kind.
        if !uncovered_query_idx.is_empty() {
            return Err(TranscriptProofBuilderError::cover(
                uncovered_query_idx,
                &self.commitment_kinds,
            ));
        }

        Ok(transcript_proof)
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

    fn cover(uncovered: QueryIdx, kinds: &[TranscriptCommitmentKind]) -> Self {
        Self {
            kind: BuilderErrorKind::Cover {
                uncovered,
                kinds: kinds.to_vec(),
            },
            source: None,
        }
    }
}

#[derive(Debug, PartialEq)]
enum BuilderErrorKind {
    Index,
    MissingCommitment,
    Cover {
        uncovered: QueryIdx,
        kinds: Vec<TranscriptCommitmentKind>,
    },
    NotSupported,
}

impl fmt::Display for TranscriptProofBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transcript proof builder error: ")?;

        match &self.kind {
            BuilderErrorKind::Index => f.write_str("index error")?,
            BuilderErrorKind::MissingCommitment => f.write_str("commitment error")?,
            BuilderErrorKind::Cover { uncovered, kinds } => f.write_str(&format!(
                "unable to cover the following ranges in transcript using available {:?} commitments: {uncovered}",
                kinds
            ))?,
            BuilderErrorKind::NotSupported => f.write_str("not supported")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[allow(clippy::single_range_in_vec_init)]
#[cfg(test)]
mod tests {
    use rangeset::RangeSet;
    use rstest::rstest;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    use crate::{
        attestation::FieldId,
        fixtures::{
            attestation_fixture, encoder_secret, encoding_provider, request_fixture,
            ConnectionFixture, RequestFixture,
        },
        hash::{Blake3, HashAlgId},
        signing::SignatureAlgId,
        transcript::TranscriptCommitConfigBuilder,
    };

    use super::*;

    #[rstest]
    fn test_verify_missing_encoding_commitment_root() {
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
            encoder_secret(),
        );

        let provider = CryptoProvider::default();
        let err = transcript_proof
            .verify_with_provider(&provider, &attestation.body)
            .err()
            .unwrap();
        assert!(matches!(err.kind, ErrorKind::Encoding));
    }

    #[rstest]
    fn test_reveal_range_out_of_bounds() {
        let transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &index);

        let err = builder.reveal(&(10..15), Direction::Sent).unwrap_err();
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

        let err = builder.reveal_recv(&(9..11)).unwrap_err();
        assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
    }

    #[rstest]
    fn test_set_commitment_kinds_with_duplicates() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let index = Index::default();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &index);
        builder.commitment_kinds(&[
            TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            },
            TranscriptCommitmentKind::Encoding,
            TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            },
            TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            },
            TranscriptCommitmentKind::Encoding,
        ]);

        assert_eq!(
            builder.commitment_kinds,
            vec![
                TranscriptCommitmentKind::Hash {
                    alg: HashAlgId::SHA256
                },
                TranscriptCommitmentKind::Encoding
            ]
        );
    }

    #[rstest]
    #[case::reveal_all_rangesets_with_exact_set(
        vec![RangeSet::from([0..10]), RangeSet::from([12..30]), RangeSet::from([0..5, 15..30]), RangeSet::from([70..75, 85..100])],
        RangeSet::from([0..10, 12..30]),
        true,
    )]
    #[case::reveal_all_rangesets_with_superset_ranges(
        vec![RangeSet::from([0..1]), RangeSet::from([1..2, 8..9]), RangeSet::from([2..4, 6..8]), RangeSet::from([2..3, 6..7]), RangeSet::from([9..12])],
        RangeSet::from([0..4, 6..9]),
        true,
    )]
    #[case::reveal_all_rangesets_with_superset_range(
        vec![RangeSet::from([0..1, 2..4]), RangeSet::from([1..3]), RangeSet::from([1..9]), RangeSet::from([2..3])],
        RangeSet::from([0..4]),
        true,
    )]
    #[case::failed_to_reveal_with_superset_range_missing_within(
        vec![RangeSet::from([0..20, 45..56]), RangeSet::from([80..120]), RangeSet::from([50..53])],
        RangeSet::from([0..120]),
        false,
    )]
    #[case::failed_to_reveal_with_superset_range_missing_outside(
        vec![RangeSet::from([2..20, 45..116]), RangeSet::from([20..45]), RangeSet::from([50..53])],
        RangeSet::from([0..120]),
        false,
    )]
    #[case::failed_to_reveal_with_superset_ranges_missing_outside(
        vec![RangeSet::from([1..10]), RangeSet::from([1..20]),  RangeSet::from([15..20, 75..110])],
        RangeSet::from([0..41, 74..100]),
        false,
    )]
    #[case::failed_to_reveal_as_no_subset_range(
        vec![RangeSet::from([2..4]), RangeSet::from([1..2]), RangeSet::from([1..9]), RangeSet::from([2..3])],
        RangeSet::from([0..1]),
        false,
    )]
    #[allow(clippy::single_range_in_vec_init)]
    fn test_reveal_mutliple_rangesets_with_one_rangeset(
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
            let err = builder.reveal_recv(&reveal_recv_rangeset).unwrap_err();
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
            .collect::<Vec<_>>()
            .into();
        let mut builder = TranscriptProofBuilder::new(&transcript, None, &plaintext_hash_secrets);
        builder.commitment_kinds(&[TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        }]);

        if success {
            assert!(builder.reveal_recv(&reveal_recv_rangeset).is_ok());
        } else {
            let err = builder.reveal_recv(&reveal_recv_rangeset).unwrap_err();
            assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
        }
    }

    #[rstest]
    fn test_reveal_commitments_from_different_kinds() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        // Commit encoding
        let encoding_rangeset = RangeSet::from(1..6);
        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        transcript_commitment_builder
            .commit_recv(&encoding_rangeset)
            .unwrap();
        // Commit hash
        let hash_rangeset = RangeSet::from(9..12);
        transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        });
        transcript_commitment_builder
            .commit_recv(&hash_rangeset)
            .unwrap();

        let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

        let encoding_tree = EncodingTree::new(
            &Blake3::default(),
            transcripts_commitment_config.iter_encoding(),
            &encoding_provider(GET_WITH_HEADER, OK_JSON),
            &transcript.length(),
        )
        .unwrap();

        let plaintext_hash_secrets: Index<PlaintextHashSecret> = transcripts_commitment_config
            .iter_hash()
            .map(|(&(direction, ref idx), _)| PlaintextHashSecret {
                direction,
                idx: idx.clone(),
                commitment: FieldId::default(),
                blinder: rand::random(),
            })
            .collect::<Vec<_>>()
            .into();

        let mut builder =
            TranscriptProofBuilder::new(&transcript, Some(&encoding_tree), &plaintext_hash_secrets);
        builder.commitment_kinds(&[
            TranscriptCommitmentKind::Hash {
                alg: HashAlgId::BLAKE3,
            },
            TranscriptCommitmentKind::Encoding,
        ]);

        // Reveal encoding commitments
        assert!(builder.reveal_recv(&encoding_rangeset).is_ok());
        // Reveal hash commitments
        assert!(builder.reveal_recv(&hash_rangeset).is_ok());
    }

    #[rstest]
    #[case::cover(
        vec![RangeSet::from([1..5, 6..10])],
        vec![RangeSet::from([2..4, 8..10])],
        RangeSet::from([1..5, 6..10]),
        RangeSet::from([2..4, 8..10]),
        RangeSet::default(),
        RangeSet::default(),
    )]
    #[case::failed_to_cover_sent(
        vec![RangeSet::from([1..5, 6..10])],
        vec![RangeSet::from([2..4, 8..10])],
        RangeSet::from([1..5]),
        RangeSet::from([2..4, 8..10]),
        RangeSet::from([1..5]),
        RangeSet::default(),
    )]
    #[case::failed_to_cover_recv(
        vec![RangeSet::from([1..5, 6..10])],
        vec![RangeSet::from([2..4, 8..10])],
        RangeSet::from([1..5, 6..10]),
        RangeSet::from([2..4]),
        RangeSet::default(),
        RangeSet::from([2..4]),
    )]
    #[case::failed_to_cover_both(
        vec![RangeSet::from([1..5, 6..10])],
        vec![RangeSet::from([2..4, 8..10])],
        RangeSet::from([1..5]),
        RangeSet::from([2..4]),
        RangeSet::from([1..5]),
        RangeSet::from([2..4]),
    )]
    #[allow(clippy::single_range_in_vec_init)]
    fn test_transcript_proof_builder(
        #[case] commit_sent_rangesets: Vec<RangeSet<usize>>,
        #[case] commit_recv_rangesets: Vec<RangeSet<usize>>,
        #[case] reveal_sent_rangeset: RangeSet<usize>,
        #[case] reveal_recv_rangeset: RangeSet<usize>,
        #[case] uncovered_sent_rangeset: RangeSet<usize>,
        #[case] uncovered_recv_rangeset: RangeSet<usize>,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        // Encoding commitment kind
        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        for rangeset in commit_sent_rangesets.iter() {
            transcript_commitment_builder.commit_sent(rangeset).unwrap();
        }
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
        builder.reveal_sent(&reveal_sent_rangeset).unwrap();
        builder.reveal_recv(&reveal_recv_rangeset).unwrap();

        if uncovered_sent_rangeset.is_empty() && uncovered_recv_rangeset.is_empty() {
            assert!(builder.build().is_ok());
        } else {
            let TranscriptProofBuilderError { kind, .. } = builder.build().unwrap_err();
            match kind {
                BuilderErrorKind::Cover { uncovered, .. } => {
                    if !uncovered_sent_rangeset.is_empty() {
                        assert_eq!(uncovered.sent, Idx(uncovered_sent_rangeset));
                    }
                    if !uncovered_recv_rangeset.is_empty() {
                        assert_eq!(uncovered.recv, Idx(uncovered_recv_rangeset));
                    }
                }
                _ => panic!("unexpected error kind: {:?}", kind),
            }
        }
    }
}
