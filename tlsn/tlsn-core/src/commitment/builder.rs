use std::collections::HashMap;

use bimap::BiMap;
use mpz_core::hash::Hash;
use utils::range::{RangeSet, ToRangeSet};

use crate::{
    commitment::{
        blake3::Blake3Commitment, Commitment, CommitmentId, CommitmentInfo, CommitmentKind,
        TranscriptCommitments,
    },
    merkle::MerkleTree,
    transcript::get_value_ids,
    Direction, EncodingProvider,
};

/// An error for [`TranscriptCommitmentBuilder`]
#[derive(Debug, thiserror::Error)]
pub enum TranscriptCommitmentBuilderError {
    /// Empty range
    #[error("can not commit to an empty range")]
    EmptyRange,
    /// Range out of bounds
    #[error("range out of bounds: {upper_commitment} > {upper_transcript}")]
    RangeOutOfBounds {
        /// The upper bound of the commitment range
        upper_commitment: usize,
        /// The upper bound of the transcript range
        upper_transcript: usize,
    },
    /// Failed to retrieve encodings for the provided transcript ranges.
    #[error("failed to retrieve encodings for the provided transcript ranges")]
    MissingEncodings,
    /// Duplicate commitment
    #[error("attempted to create a duplicate commitment, overwriting: {0:?}")]
    Duplicate(CommitmentId),
    /// No commitments were added
    #[error("no commitments were added")]
    NoCommitments,
}

/// A builder for [`TranscriptCommitments`].
pub struct TranscriptCommitmentBuilder {
    commitments: HashMap<CommitmentId, Commitment>,
    /// Information about the above `commitments`.
    commitment_info: BiMap<CommitmentId, CommitmentInfo>,
    merkle_leaves: Vec<Hash>,
    /// A function that returns the encodings for the provided transcript byte ids.
    encoding_provider: EncodingProvider,
    sent_len: usize,
    recv_len: usize,
}

opaque_debug::implement!(TranscriptCommitmentBuilder);

impl TranscriptCommitmentBuilder {
    /// Creates a new builder.
    ///
    /// # Arguments
    ///
    /// * `encoding_provider` - A function that returns the encodings for the provided transcript byte ids.
    #[doc(hidden)]
    pub fn new(encoding_provider: EncodingProvider, sent_len: usize, recv_len: usize) -> Self {
        Self {
            commitments: HashMap::default(),
            commitment_info: BiMap::default(),
            merkle_leaves: Vec::default(),
            encoding_provider,
            sent_len,
            recv_len,
        }
    }

    /// Commits to the provided ranges of the `sent` transcript.
    pub fn commit_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<CommitmentId, TranscriptCommitmentBuilderError> {
        self.add_substrings_commitment(&ranges.to_range_set(), Direction::Sent)
    }

    /// Commits to the provided ranges of the `received` transcript.
    pub fn commit_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<CommitmentId, TranscriptCommitmentBuilderError> {
        self.add_substrings_commitment(&ranges.to_range_set(), Direction::Received)
    }

    /// Commits to the provided ranges of the transcript.
    pub fn commit(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<CommitmentId, TranscriptCommitmentBuilderError> {
        match direction {
            Direction::Sent => self.commit_sent(ranges),
            Direction::Received => self.commit_recv(ranges),
        }
    }

    /// Gets the commitment id for the provided commitment info.
    pub fn get_id(
        &self,
        kind: CommitmentKind,
        ranges: impl Into<RangeSet<usize>>,
        direction: Direction,
    ) -> Option<CommitmentId> {
        self.commitment_info
            .get_by_right(&CommitmentInfo {
                kind,
                ranges: ranges.into(),
                direction,
            })
            .copied()
    }

    /// Add a commitment to substrings of the transcript
    fn add_substrings_commitment(
        &mut self,
        ranges: &RangeSet<usize>,
        direction: Direction,
    ) -> Result<CommitmentId, TranscriptCommitmentBuilderError> {
        let max = ranges
            .max()
            .ok_or(TranscriptCommitmentBuilderError::EmptyRange)?;
        let len = match direction {
            Direction::Sent => self.sent_len,
            Direction::Received => self.recv_len,
        };

        if max > len {
            return Err(TranscriptCommitmentBuilderError::RangeOutOfBounds {
                upper_commitment: max,
                upper_transcript: len,
            });
        }

        let ids: Vec<_> = get_value_ids(ranges, direction).collect();

        let id_refs = ids.iter().map(|id| id.as_ref()).collect::<Vec<_>>();

        let encodings = (self.encoding_provider)(&id_refs)
            .ok_or(TranscriptCommitmentBuilderError::MissingEncodings)?;

        // We only support BLAKE3 for now
        let commitment = Blake3Commitment::new(&encodings);
        let hash = *commitment.hash();

        let id = CommitmentId::new(self.merkle_leaves.len() as u32);

        let commitment: Commitment = commitment.into();

        // Store commitment with its id
        self.commitment_info
            .insert_no_overwrite(
                id,
                CommitmentInfo::new(commitment.kind(), ranges.clone(), direction),
            )
            .map_err(|(id, _)| TranscriptCommitmentBuilderError::Duplicate(id))?;

        if self.commitments.insert(id, commitment).is_some() {
            // This shouldn't be possible, as we check for duplicates above.
            panic!("commitment id already exists");
        }

        // Insert commitment hash into the merkle tree
        self.merkle_leaves.push(hash);

        Ok(id)
    }

    /// Builds the [`TranscriptCommitments`]
    pub fn build(self) -> Result<TranscriptCommitments, TranscriptCommitmentBuilderError> {
        let Self {
            commitments,
            commitment_info,
            merkle_leaves,
            ..
        } = self;

        let merkle_tree = MerkleTree::from_leaves(&merkle_leaves)
            .map_err(|_| TranscriptCommitmentBuilderError::NoCommitments)?;

        Ok(TranscriptCommitments {
            merkle_tree,
            commitments,
            commitment_info,
        })
    }
}
