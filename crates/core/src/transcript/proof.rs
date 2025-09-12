//! Transcript proofs.

use rangeset::{Cover, Difference, Subset, ToRangeSet, UnionMut};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

use crate::{
    connection::TranscriptLength,
    display::FmtRangeSet,
    hash::{HashAlgId, HashProvider},
    transcript::{
        commit::{TranscriptCommitment, TranscriptCommitmentKind},
        encoding::{EncodingProof, EncodingProofError, EncodingTree},
        hash::{hash_plaintext, PlaintextHash, PlaintextHashSecret},
        Direction, PartialTranscript, RangeSet, Transcript, TranscriptSecret,
    },
};

/// Default commitment kinds in order of preference for building transcript
/// proofs.
const DEFAULT_COMMITMENT_KINDS: &[TranscriptCommitmentKind] = &[
    TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    },
    TranscriptCommitmentKind::Encoding,
];

/// Proof of the contents of a transcript.
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptProof {
    transcript: PartialTranscript,
    encoding_proof: Option<EncodingProof>,
    hash_secrets: Vec<PlaintextHashSecret>,
}

opaque_debug::implement!(TranscriptProof);

impl TranscriptProof {
    /// Verifies the proof.
    ///
    /// Returns a partial transcript of authenticated data.
    ///
    /// # Arguments
    ///
    /// * `provider` - The hash provider to use for verification.
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify_with_provider<'a>(
        self,
        provider: &HashProvider,
        length: &TranscriptLength,
        commitments: impl IntoIterator<Item = &'a TranscriptCommitment>,
    ) -> Result<PartialTranscript, TranscriptProofError> {
        let mut encoding_commitment = None;
        let mut hash_commitments = HashSet::new();
        // Index commitments.
        for commitment in commitments {
            match commitment {
                TranscriptCommitment::Encoding(commitment) => {
                    if encoding_commitment.replace(commitment).is_some() {
                        return Err(TranscriptProofError::new(
                            ErrorKind::Encoding,
                            "multiple encoding commitments are present.",
                        ));
                    }
                }
                TranscriptCommitment::Hash(plaintext_hash) => {
                    hash_commitments.insert(plaintext_hash);
                }
            }
        }

        if self.transcript.sent_unsafe().len() != length.sent as usize
            || self.transcript.received_unsafe().len() != length.received as usize
        {
            return Err(TranscriptProofError::new(
                ErrorKind::Proof,
                "transcript has incorrect length",
            ));
        }

        let mut total_auth_sent = RangeSet::default();
        let mut total_auth_recv = RangeSet::default();

        // Verify encoding proof.
        if let Some(proof) = self.encoding_proof {
            let commitment = encoding_commitment.ok_or_else(|| {
                TranscriptProofError::new(
                    ErrorKind::Encoding,
                    "contains an encoding proof but missing encoding commitment",
                )
            })?;

            let (auth_sent, auth_recv) = proof.verify_with_provider(
                provider,
                commitment,
                self.transcript.sent_unsafe(),
                self.transcript.received_unsafe(),
            )?;

            total_auth_sent.union_mut(&auth_sent);
            total_auth_recv.union_mut(&auth_recv);
        }

        let mut buffer = Vec::new();
        for PlaintextHashSecret {
            direction,
            idx,
            alg,
            blinder,
        } in self.hash_secrets
        {
            let hasher = provider.get(&alg).map_err(|_| {
                TranscriptProofError::new(
                    ErrorKind::Hash,
                    format!("hash opening has unknown algorithm: {alg}"),
                )
            })?;

            let (plaintext, auth) = match direction {
                Direction::Sent => (self.transcript.sent_unsafe(), &mut total_auth_sent),
                Direction::Received => (self.transcript.received_unsafe(), &mut total_auth_recv),
            };

            if idx.end().unwrap_or(0) > plaintext.len() {
                return Err(TranscriptProofError::new(
                    ErrorKind::Hash,
                    "hash opening index is out of bounds",
                ));
            }

            buffer.clear();
            for range in idx.iter_ranges() {
                buffer.extend_from_slice(&plaintext[range]);
            }

            let expected = PlaintextHash {
                direction,
                idx,
                hash: hash_plaintext(hasher, &buffer, &blinder),
            };

            if !hash_commitments.contains(&expected) {
                return Err(TranscriptProofError::new(
                    ErrorKind::Hash,
                    "hash opening does not match any commitment",
                ));
            }

            auth.union_mut(&expected.idx);
        }

        // Assert that all the authenticated data are covered by the proof.
        if &total_auth_sent != self.transcript.sent_authed()
            || &total_auth_recv != self.transcript.received_authed()
        {
            return Err(TranscriptProofError::new(
                ErrorKind::Proof,
                "transcript proof contains unauthenticated data",
            ));
        }

        Ok(self.transcript)
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
    Proof,
}

impl fmt::Display for TranscriptProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("transcript proof error: ")?;

        match self.kind {
            ErrorKind::Encoding => f.write_str("encoding error")?,
            ErrorKind::Hash => f.write_str("hash error")?,
            ErrorKind::Proof => f.write_str("proof error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<EncodingProofError> for TranscriptProofError {
    fn from(e: EncodingProofError) -> Self {
        TranscriptProofError::new(ErrorKind::Encoding, e)
    }
}

/// Union of ranges to reveal.
#[derive(Clone, Debug, PartialEq)]
struct QueryIdx {
    sent: RangeSet<usize>,
    recv: RangeSet<usize>,
}

impl QueryIdx {
    fn new() -> Self {
        Self {
            sent: RangeSet::default(),
            recv: RangeSet::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.sent.is_empty() && self.recv.is_empty()
    }

    fn union(&mut self, direction: &Direction, other: &RangeSet<usize>) {
        match direction {
            Direction::Sent => self.sent.union_mut(other),
            Direction::Received => self.recv.union_mut(other),
        }
    }
}

impl std::fmt::Display for QueryIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sent: {}, received: {}",
            FmtRangeSet(&self.sent),
            FmtRangeSet(&self.recv)
        )
    }
}

/// Builder for [`TranscriptProof`].
#[derive(Debug)]
pub struct TranscriptProofBuilder<'a> {
    /// Commitment kinds in order of preference for building transcript proofs.
    commitment_kinds: Vec<TranscriptCommitmentKind>,
    transcript: &'a Transcript,
    encoding_tree: Option<&'a EncodingTree>,
    hash_secrets: Vec<&'a PlaintextHashSecret>,
    committed_sent: RangeSet<usize>,
    committed_recv: RangeSet<usize>,
    query_idx: QueryIdx,
}

impl<'a> TranscriptProofBuilder<'a> {
    /// Creates a new proof builder.
    pub fn new(
        transcript: &'a Transcript,
        secrets: impl IntoIterator<Item = &'a TranscriptSecret>,
    ) -> Self {
        let mut committed_sent = RangeSet::default();
        let mut committed_recv = RangeSet::default();

        let mut encoding_tree = None;
        let mut hash_secrets = Vec::new();
        for secret in secrets {
            match secret {
                TranscriptSecret::Encoding(tree) => {
                    committed_sent.union_mut(tree.idx(Direction::Sent));
                    committed_recv.union_mut(tree.idx(Direction::Received));
                    encoding_tree = Some(tree);
                }
                TranscriptSecret::Hash(hash) => {
                    match hash.direction {
                        Direction::Sent => committed_sent.union_mut(&hash.idx),
                        Direction::Received => committed_recv.union_mut(&hash.idx),
                    }
                    hash_secrets.push(hash);
                }
            }
        }

        Self {
            commitment_kinds: DEFAULT_COMMITMENT_KINDS.to_vec(),
            transcript,
            encoding_tree,
            hash_secrets,
            committed_sent,
            committed_recv,
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
        let idx = ranges.to_range_set();

        if idx.end().unwrap_or(0) > self.transcript.len_of_direction(direction) {
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::Index,
                format!(
                    "range is out of bounds of the transcript ({}): {} > {}",
                    direction,
                    idx.end().unwrap_or(0),
                    self.transcript.len_of_direction(direction)
                ),
            ));
        }

        let committed = match direction {
            Direction::Sent => &self.committed_sent,
            Direction::Received => &self.committed_recv,
        };

        if idx.is_subset(committed) {
            self.query_idx.union(&direction, &idx);
        } else {
            let missing = idx.difference(committed);
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::MissingCommitment,
                format!(
                    "commitment is missing for ranges in {direction} transcript: {}",
                    FmtRangeSet(&missing)
                ),
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
            transcript: self
                .transcript
                .to_partial(self.query_idx.sent.clone(), self.query_idx.recv.clone()),
            encoding_proof: None,
            hash_secrets: Vec::new(),
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

                        let (sent_dir_idxs, sent_uncovered) = uncovered_query_idx.sent.cover_by(
                            encoding_tree
                                .transcript_indices()
                                .filter(|(dir, _)| *dir == Direction::Sent),
                            |(_, idx)| idx,
                        );
                        // Uncovered ranges will be checked with ranges of the next
                        // preferred commitment kind.
                        uncovered_query_idx.sent = sent_uncovered;

                        let (recv_dir_idxs, recv_uncovered) = uncovered_query_idx.recv.cover_by(
                            encoding_tree
                                .transcript_indices()
                                .filter(|(dir, _)| *dir == Direction::Received),
                            |(_, idx)| idx,
                        );
                        uncovered_query_idx.recv = recv_uncovered;

                        let dir_idxs = sent_dir_idxs
                            .into_iter()
                            .chain(recv_dir_idxs)
                            .collect::<Vec<_>>();

                        // Skip proof generation if there are no committed ranges that can cover the
                        // query ranges.
                        if !dir_idxs.is_empty() {
                            transcript_proof.encoding_proof = Some(
                                encoding_tree
                                    .proof(dir_idxs.into_iter())
                                    .expect("subsequences were checked to be in tree"),
                            );
                        }
                    }
                    TranscriptCommitmentKind::Hash { alg } => {
                        let (sent_hashes, sent_uncovered) = uncovered_query_idx.sent.cover_by(
                            self.hash_secrets.iter().filter(|hash| {
                                hash.direction == Direction::Sent && &hash.alg == alg
                            }),
                            |hash| &hash.idx,
                        );
                        // Uncovered ranges will be checked with ranges of the next
                        // preferred commitment kind.
                        uncovered_query_idx.sent = sent_uncovered;

                        let (recv_hashes, recv_uncovered) = uncovered_query_idx.recv.cover_by(
                            self.hash_secrets.iter().filter(|hash| {
                                hash.direction == Direction::Received && &hash.alg == alg
                            }),
                            |hash| &hash.idx,
                        );
                        uncovered_query_idx.recv = recv_uncovered;

                        transcript_proof.hash_secrets.extend(
                            sent_hashes
                                .into_iter()
                                .map(|s| PlaintextHashSecret::clone(s)),
                        );
                        transcript_proof.hash_secrets.extend(
                            recv_hashes
                                .into_iter()
                                .map(|s| PlaintextHashSecret::clone(s)),
                        );
                    }
                    #[allow(unreachable_patterns)]
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
                "unable to cover the following ranges in transcript using available {kinds:?} commitments: {uncovered}"
            ))?,
            BuilderErrorKind::NotSupported => f.write_str("not supported")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

#[allow(clippy::single_range_in_vec_init)]
#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rangeset::RangeSet;
    use rstest::rstest;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    use crate::{
        fixtures::encoding_provider,
        hash::{Blake3, Blinder, HashAlgId},
        transcript::TranscriptCommitConfigBuilder,
    };

    use super::*;

    #[rstest]
    fn test_verify_missing_encoding_commitment_root() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let idxs = vec![(Direction::Received, RangeSet::from(0..transcript.len().1))];
        let encoding_tree = EncodingTree::new(
            &Blake3::default(),
            &idxs,
            &encoding_provider(transcript.sent(), transcript.received()),
        )
        .unwrap();

        let secrets = vec![TranscriptSecret::Encoding(encoding_tree)];
        let mut builder = TranscriptProofBuilder::new(&transcript, &secrets);

        builder.reveal_recv(&(0..transcript.len().1)).unwrap();

        let transcript_proof = builder.build().unwrap();

        let provider = HashProvider::default();
        let err = transcript_proof
            .verify_with_provider(&provider, &transcript.length(), &[])
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
        let mut builder = TranscriptProofBuilder::new(&transcript, &[]);

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
        let mut builder = TranscriptProofBuilder::new(&transcript, &[]);

        let err = builder.reveal_recv(&(9..11)).unwrap_err();
        assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
    }

    #[rstest]
    fn test_reveal_with_hash_commitment() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let provider = HashProvider::default();
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        let direction = Direction::Sent;
        let idx = RangeSet::from(0..10);
        let blinder: Blinder = rng.random();
        let alg = HashAlgId::SHA256;
        let hasher = provider.get(&alg).unwrap();

        let commitment = PlaintextHash {
            direction,
            idx: idx.clone(),
            hash: hash_plaintext(hasher, &transcript.sent()[0..10], &blinder),
        };

        let secret = PlaintextHashSecret {
            direction,
            idx: idx.clone(),
            alg,
            blinder,
        };

        let secrets = vec![TranscriptSecret::Hash(secret)];
        let mut builder = TranscriptProofBuilder::new(&transcript, &secrets);

        builder.reveal_sent(&(0..10)).unwrap();

        let transcript_proof = builder.build().unwrap();

        let partial_transcript = transcript_proof
            .verify_with_provider(
                &provider,
                &transcript.length(),
                &[TranscriptCommitment::Hash(commitment)],
            )
            .unwrap();

        assert_eq!(
            partial_transcript.sent_unsafe()[0..10],
            transcript.sent()[0..10]
        );
    }

    #[rstest]
    fn test_reveal_with_inconsistent_hash_commitment() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let provider = HashProvider::default();
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        let direction = Direction::Sent;
        let idx = RangeSet::from(0..10);
        let blinder: Blinder = rng.random();
        let alg = HashAlgId::SHA256;
        let hasher = provider.get(&alg).unwrap();

        let commitment = PlaintextHash {
            direction,
            idx: idx.clone(),
            hash: hash_plaintext(hasher, &transcript.sent()[0..10], &blinder),
        };

        let secret = PlaintextHashSecret {
            direction,
            idx: idx.clone(),
            alg,
            // Use a different blinder to create an inconsistent commitment
            blinder: rng.random(),
        };

        let secrets = vec![TranscriptSecret::Hash(secret)];
        let mut builder = TranscriptProofBuilder::new(&transcript, &secrets);

        builder.reveal_sent(&(0..10)).unwrap();

        let transcript_proof = builder.build().unwrap();

        let err = transcript_proof
            .verify_with_provider(
                &provider,
                &transcript.length(),
                &[TranscriptCommitment::Hash(commitment)],
            )
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Hash));
    }

    #[rstest]
    fn test_set_commitment_kinds_with_duplicates() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let mut builder = TranscriptProofBuilder::new(&transcript, &[]);
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
        )
        .unwrap();

        let secrets = vec![TranscriptSecret::Encoding(encoding_tree)];
        let mut builder = TranscriptProofBuilder::new(&transcript, &secrets);

        if success {
            assert!(builder.reveal_recv(&reveal_recv_rangeset).is_ok());
        } else {
            let err = builder.reveal_recv(&reveal_recv_rangeset).unwrap_err();
            assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
        }
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
        )
        .unwrap();

        let secrets = vec![TranscriptSecret::Encoding(encoding_tree)];
        let mut builder = TranscriptProofBuilder::new(&transcript, &secrets);
        builder.reveal_sent(&reveal_sent_rangeset).unwrap();
        builder.reveal_recv(&reveal_recv_rangeset).unwrap();

        if uncovered_sent_rangeset.is_empty() && uncovered_recv_rangeset.is_empty() {
            assert!(builder.build().is_ok());
        } else {
            let TranscriptProofBuilderError { kind, .. } = builder.build().unwrap_err();
            match kind {
                BuilderErrorKind::Cover { uncovered, .. } => {
                    if !uncovered_sent_rangeset.is_empty() {
                        assert_eq!(uncovered.sent, uncovered_sent_rangeset);
                    }
                    if !uncovered_recv_rangeset.is_empty() {
                        assert_eq!(uncovered.recv, uncovered_recv_rangeset);
                    }
                }
                _ => panic!("unexpected error kind: {kind:?}"),
            }
        }
    }
}
