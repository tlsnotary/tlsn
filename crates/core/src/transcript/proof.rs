//! Transcript proofs.

use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{hash_set::Iter, HashSet},
    fmt,
    ops::Range,
};
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

/// A wrapper on [Idx].
///
/// This is purely used for [ProofIdxs::prune_subset]. An effective sort of
/// [Idx] is needed there to reduce the time complexity to prune subset(s) from
/// a collection of [Idx].
///
/// A custom ordering logic is implemented for [OrderedIdx] to achieve that (see
/// [Ord] implementation below). As a result, for each [OrderedIdx] in this
/// sorted collection, a full on subset check only needs to be done with other
/// [OrderedIdx] that are bigger than itself. This is faster than
/// conducting the check with every other [OrderedIdx] in the collection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct OrderedIdx(Idx);

impl OrderedIdx {
    fn new(idx: Idx) -> Self {
        Self(idx)
    }

    fn inner(&self) -> &Idx {
        &self.0
    }

    fn into_inner(self) -> Idx {
        self.0
    }

    fn is_subset(&self, other: &OrderedIdx) -> bool {
        self.0.is_subset(other.inner())
    }

    fn iter_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.0.iter_ranges()
    }
}

/// Custom ordering for [OrderedIdx].
///
/// [OrderedIdx] is ordered in terms of its likelihood to be a subset of other,
/// where [OrderedIdx] with higher likelihood to be a subset of other, is
/// smaller. For example,
///
/// (a) [4..5, 7..9] is smaller than [1..5, 6..10].
/// (b) [7..9, 10..13] is smaller than [7..10, 12..15].
/// (c) [1..3, 5..9] is smaller than [1..3, 4..10].
///
/// Instead of a full on subset check, a cheaper 'subset likelihood' check is
/// used for this. Note that this doesn't guarantee that the smaller
/// [OrderedIdx] is always a subset, e.g. example (b).
impl Ord for OrderedIdx {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut self_ranges_iter = self.iter_ranges();
        let mut other_ranges_iter = other.iter_ranges();

        let mut self_range_option = self_ranges_iter.next();
        let mut other_range_option = other_ranges_iter.next();

        // Iterate from the respective first range of [self] and [other], return
        // immediately if their start or end are different.
        while self_range_option.is_some() && other_range_option.is_some() {
            let self_range = self_range_option.unwrap();
            let other_range = other_range_option.unwrap();

            // Compare the start of the range (start..end) between the nth range of [self]
            // and [other], where bigger start = higher likelihood to be a
            // subset. For example, 4..x is likely to be a subset of 1..y, but
            // 1..y cannot be a subset of 4..x.
            if self_range.start != other_range.start {
                // reverse() as bigger start = more likely to be subset = smaller [OrderedIdx].
                return self_range.start.cmp(&other_range.start).reverse();
            }

            // If start is the same, then the end of the range (start..end) is compared.
            // Smaller end = higher likelihood to be a subset. For example, x..4 is likely
            // to be a subset of x..5, but x..5 cannot be a subset of x..4.
            if self_range.end != other_range.end {
                return self_range.end.cmp(&other_range.end);
            }

            self_range_option = self_ranges_iter.next();
            other_range_option = other_ranges_iter.next();
        }

        match (self_range_option, other_range_option) {
            // All N ranges of [other] are the same as the first N ranges of [self],
            // i.e. [other] is a subset of [self].
            (Some(_), None) => Ordering::Greater,
            // All N ranges of [self] are the same as the first N ranges of [other],
            // i.e. [self] is a subset of [other].
            (None, Some(_)) => Ordering::Less,
            // All ranges of [self] are the same as all ranges of [other].
            (None, None) => Ordering::Equal,
            (Some(_), Some(_)) => {
                unreachable!("self_range_option and other_range_option cannot be both some")
            }
        }
    }
}

impl PartialOrd for OrderedIdx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A wrapper to store and process ([Direction], [Idx]) to be revealed.
#[derive(Debug)]
struct ProofIdxs(HashSet<(Direction, Idx)>);

impl ProofIdxs {
    fn new() -> Self {
        Self(HashSet::default())
    }

    fn insert(&mut self, dir_idx: (Direction, Idx)) -> bool {
        self.0.insert(dir_idx)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> Iter<'_, (Direction, Idx)> {
        self.0.iter()
    }

    /// Prune any rangeset [Idx] that is a subset of another rangeset before
    /// constructing [EncodingProof] or [PlaintextHashProof] to reduce
    /// unnecessary proof size, and proving + verifying time later.
    ///
    /// This is because any subset rangeset would also be revealed by its
    /// superset rangeset.
    fn prune_subset(&mut self) {
        self.prune_subset_with_direction(Direction::Sent);
        self.prune_subset_with_direction(Direction::Received);
    }

    fn prune_subset_with_direction(&mut self, direction: Direction) {
        // Given a specific [Direction], collect relevant [Idx] and build [OrderedIdx].
        let mut idxs_to_prune = self
            .iter()
            .filter(|(dir, _)| *dir == direction)
            .map(|(_, idx)| OrderedIdx::new(idx.clone()))
            .collect::<Vec<_>>();

        // Sort the collection according to the custom ordering described in [Ord]
        // implementation of [OrderedIdx] — which reduces subset search
        // time complexity.
        idxs_to_prune.sort_unstable();

        // Reverse the order so that subset check of each [OrderedIdx] is done with the
        // most likely superset (the biggest) first.
        idxs_to_prune.reverse();

        // [OrderedIdx] to be pruned and excluded.
        let mut pruned_idxs = HashSet::new();

        // Start from the second [OrderedIdx], as the first is guaranteed to not be a
        // subset of any.
        for i in 1..idxs_to_prune.len() {
            let idx = &idxs_to_prune[i];

            // Perform subset check of [idx] with [other_idx] that are bigger, as [idx]
            // is only likely to be their subset.
            for other_idx in idxs_to_prune.iter().take(i) {
                // Remove [idx] if it's a subset — this check contains an inner loop, which is
                // why the custom-ordering sort is used to minimise the no. of iteration of
                // the current loop.
                if !pruned_idxs.contains(other_idx) && idx.is_subset(other_idx) {
                    pruned_idxs.insert(idx);
                }
            }
        }

        pruned_idxs.into_iter().for_each(|idx| {
            self.0.remove(&(direction, idx.clone().into_inner()));
        });
    }
}

/// Builder for [`TranscriptProof`].
#[derive(Debug)]
pub struct TranscriptProofBuilder<'a> {
    default_kind: TranscriptCommitmentKind,
    transcript: &'a Transcript,
    encoding_tree: Option<&'a EncodingTree>,
    plaintext_hashes: &'a Index<PlaintextHashSecret>,
    encoding_proof_idxs: ProofIdxs,
    hash_proof_idxs: ProofIdxs,
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
            encoding_proof_idxs: ProofIdxs::new(),
            hash_proof_idxs: ProofIdxs::new(),
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

        let dir_idx = (direction, idx);

        match kind {
            TranscriptCommitmentKind::Encoding => {
                let Some(encoding_tree) = self.encoding_tree else {
                    return Err(TranscriptProofBuilderError::new(
                        BuilderErrorKind::MissingCommitment,
                        "encoding tree is missing",
                    ));
                };

                // Insert the rangeset [dir_idx] if it's in the encoding tree, i.e. it's
                // committed.
                if encoding_tree.contains(&dir_idx) {
                    self.encoding_proof_idxs.insert(dir_idx);
                } else {
                    // Check if there is any committed rangeset in the encoding tree that is a
                    // subset of [dir_idx] — if yes, stage them into a temporary collection
                    // first.
                    let mut staged_subsets = Vec::new();
                    for committed_dir_idx in encoding_tree
                        .transcript_indices()
                        .into_iter()
                        .filter(|(dir, _)| *dir == dir_idx.0)
                    {
                        if committed_dir_idx.1.is_subset(&dir_idx.1) {
                            staged_subsets.push(committed_dir_idx);
                        }
                    }

                    // Form a union of all the staged subsets.
                    let mut union_subsets = Idx::empty();
                    for &(_, idx) in staged_subsets.iter() {
                        union_subsets = union_subsets.union(idx);
                    }

                    // Check if the union equals to [dir_idx] — if yes, that means [dir_idx]
                    // can be revealed as it is fully covered by the staged committed subsets.
                    if union_subsets == dir_idx.1 {
                        staged_subsets.into_iter().for_each(|commited_dir_idx| {
                            self.encoding_proof_idxs.insert(commited_dir_idx.clone());
                        });
                    // If no, that means either
                    // (1) No subset found.
                    // (2) There are ranges in [dir_idx] that are not covered by
                    // the staged subsets, hence
                    //     [dir_idx] cannot be revealed.
                    } else {
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
                // Insert the rangeset [dir_idx] if it's in [plaintext_hashes], i.e. it's
                // committed.
                if self
                    .plaintext_hashes
                    .get_by_transcript_idx(&dir_idx)
                    .is_some()
                {
                    self.hash_proof_idxs.insert(dir_idx);
                } else {
                    // Check if there is any committed rangeset in [plaintext_hashes] that is a
                    // subset of [dir_idx] — if yes, stage them into a temporary collection
                    // first.
                    let mut staged_subsets = Vec::new();
                    for committed_secret in self
                        .plaintext_hashes
                        .iter()
                        .filter(|secret| secret.direction == dir_idx.0)
                    {
                        if committed_secret.idx.is_subset(&dir_idx.1) {
                            staged_subsets
                                .push((committed_secret.direction, &committed_secret.idx));
                        }
                    }

                    // Form a union of all the staged subsets.
                    let mut union_subsets = Idx::empty();
                    for &(_, idx) in staged_subsets.iter() {
                        union_subsets = union_subsets.union(idx);
                    }

                    // Check if the union equals to [dir_idx] — if yes, that means [dir_idx]
                    // can be revealed as it is fully covered by the staged committed subsets.
                    if union_subsets == dir_idx.1 {
                        staged_subsets.into_iter().for_each(|commited_dir_idx| {
                            self.hash_proof_idxs
                                .insert((commited_dir_idx.0, commited_dir_idx.1.clone()));
                        });
                    // If no, that means either
                    // (1) No subset found.
                    // (2) There are ranges in [dir_idx] that are not covered by
                    // the staged subsets, hence
                    //     [dir_idx] cannot be revealed.
                    } else {
                        return Err(TranscriptProofBuilderError::new(
                            BuilderErrorKind::MissingCommitment,
                            format!(
                                "hash commitment is missing for ranges in {} transcript",
                                direction
                            ),
                        ));
                    }
                }
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
    pub fn build(mut self) -> Result<TranscriptProof, TranscriptProofBuilderError> {
        let encoding_proof = if !self.encoding_proof_idxs.is_empty() {
            self.encoding_proof_idxs.prune_subset();

            let encoding_tree = self.encoding_tree.expect("encoding tree is present");

            let proof = encoding_tree
                .proof(self.transcript, self.encoding_proof_idxs.iter())
                .expect("subsequences were checked to be in tree");

            Some(proof)
        } else {
            None
        };

        let mut hash_proofs = Vec::new();
        if !self.hash_proof_idxs.is_empty() {
            self.hash_proof_idxs.prune_subset();

            for dir_idx in self.hash_proof_idxs.iter() {
                let PlaintextHashSecret {
                    commitment,
                    blinder,
                    ..
                } = self
                    .plaintext_hashes
                    .get_by_transcript_idx(dir_idx)
                    .expect("idx was checked to be committed");

                let (_, data) = self
                    .transcript
                    .get(dir_idx.0, &dir_idx.1)
                    .expect("subsequence was checked to be in transcript")
                    .into_parts();

                hash_proofs.push(PlaintextHashProof::new(
                    Blinded::new_with_blinder(data, blinder.clone()),
                    *commitment,
                ));
            }
        }

        Ok(TranscriptProof {
            encoding_proof,
            hash_proofs,
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

#[allow(clippy::single_range_in_vec_init)]
#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};
    use utils::range::RangeSet;

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
    fn test_reveal_missing_hash_commitment_range() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        });
        transcript_commitment_builder
            .commit_recv(&(0..transcript.len().1))
            .unwrap();

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

        let err = builder.reveal_recv(&(0..11)).err().unwrap();
        assert!(matches!(err.kind, BuilderErrorKind::MissingCommitment));
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
    #[case::failed_to_reveal_with_superset_ranges(
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

    #[rstest]
    #[case::no_subset_range(
        vec![RangeSet::from([0..5]), RangeSet::from([4..40, 99..145]), RangeSet::from([40..59]), RangeSet::from([59..109])],
        None
    )]
    #[case::contains_single_subset_range(
        vec![RangeSet::from([0..40, 99..145]), RangeSet::from([11..20]), RangeSet::from([40..99])],
        Some(vec![RangeSet::from([11..20])])
    )]
    #[case::contains_multiple_subset_ranges(
        vec![RangeSet::from([0..51, 69..145]), RangeSet::from([0..30, 99..145]), RangeSet::from([51..69])],
        Some(vec![RangeSet::from([0..30, 99..145])])
    )]
    // Also tests [Ord] implementation for [Idx].
    #[case::contains_multiple_subset_rangesets(
        vec![RangeSet::from([0..7, 13..31, 49..145]), RangeSet::from([7..13, 31..49]), RangeSet::from([0..7, 14..30]), RangeSet::from([0..7, 13..29]), RangeSet::from([0..7, 13..31, 50..70]), RangeSet::from([0..7, 13..31])],
        Some(vec![RangeSet::from([0..7, 14..30]), RangeSet::from([0..7, 13..29]), RangeSet::from([0..7, 13..31, 50..70]), RangeSet::from([0..7, 13..31])])
    )]
    fn test_prune_proof_idxs_direction(
        #[case] commit_recv_rangesets: Vec<RangeSet<usize>>,
        #[case] expected_pruned_subsets: Option<Vec<RangeSet<usize>>>,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);

        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        // Commit the rangesets.
        for rangeset in &commit_recv_rangesets {
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

        // Reveal all committed rangesets via a superset rangeset.
        builder.reveal_recv(&RangeSet::from([0..145])).unwrap();

        let commit_recv_rangesets: HashSet<_> = commit_recv_rangesets.into_iter().collect();
        let initial_proof_idxs = builder
            .encoding_proof_idxs
            .iter()
            .filter(|(dir, _)| *dir == Direction::Received)
            .map(|(_, idx)| idx.clone().0)
            .collect::<HashSet<_>>();

        // Since all committed rangesets are revealed, before pruning,
        // proof_idxs should contain all committed rangesets.
        assert_eq!(commit_recv_rangesets, initial_proof_idxs);

        // Prune any subset.
        builder.encoding_proof_idxs.prune_subset();

        let pruned_proof_idxs = builder
            .encoding_proof_idxs
            .iter()
            .filter(|(dir, _)| *dir == Direction::Received)
            .map(|(_, idx)| idx.clone().0)
            .collect::<HashSet<_>>();

        if let Some(subsets) = expected_pruned_subsets {
            let pruned_subsets: HashSet<_> = commit_recv_rangesets
                .difference(&pruned_proof_idxs)
                .collect();
            assert_eq!(pruned_subsets, subsets.iter().collect());
        } else {
            assert_eq!(commit_recv_rangesets, pruned_proof_idxs);
        };
    }
}
