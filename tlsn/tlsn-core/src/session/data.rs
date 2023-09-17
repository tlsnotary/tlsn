use std::collections::HashMap;

use crate::{
    commitment::{
        blake3::Blake3Commitment, Commitment, CommitmentId, CommitmentInfo, CommitmentKind,
    },
    merkle::{MerkleError, MerkleTree},
    proof::SubstringsProofBuilder,
    Direction, Transcript,
};
use bimap::BiMap;
use mpz_core::{commit::Decommitment, hash::Hash};
use mpz_garble_core::{encoding_state, EncodedValue};
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;
use utils::range::RangeSet;

/// A builder for [`SessionData`]
pub struct SessionDataBuilder {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    transcript_tx: Transcript,
    transcript_rx: Transcript,
    merkle_leaves: Vec<Hash>,
    commitments: HashMap<CommitmentId, Commitment>,
    commitment_info: BiMap<CommitmentId, CommitmentInfo>,
}

opaque_debug::implement!(SessionDataBuilder);

/// An error for [`SessionDataBuilder`]
#[derive(Debug, thiserror::Error)]
pub enum SessionDataBuilderError {
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
}

/// A commitment error.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// The provided ranges and encodings have different lengths.
    #[error("ranges and encodings must have the same length: {0} != {1}")]
    EncodingLengthMismatch(usize, usize),
    /// Duplicate commitment
    #[error("Attempted to create a duplicate commitment, overwriting: {0:?}")]
    DuplicateCommitment(CommitmentId),
}

impl SessionDataBuilder {
    /// Creates a new builder
    pub fn new(
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
    ) -> Self {
        Self {
            handshake_data_decommitment,
            transcript_tx,
            transcript_rx,
            merkle_leaves: Vec::default(),
            commitments: HashMap::default(),
            commitment_info: BiMap::default(),
        }
    }

    /// Returns a reference to the sent data transcript.
    pub fn sent_transcript(&self) -> &Transcript {
        &self.transcript_tx
    }

    /// Returns a reference to the received data transcript.
    pub fn recv_transcript(&self) -> &Transcript {
        &self.transcript_rx
    }

    /// Add a commitment to substrings of the transcript
    pub fn add_substrings_commitment(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
        encodings: &[EncodedValue<encoding_state::Active>],
    ) -> Result<CommitmentId, SessionDataBuilderError> {
        if ranges.len() != encodings.len() {
            return Err(CommitmentError::EncodingLengthMismatch(
                ranges.len(),
                encodings.len(),
            ))?;
        }

        // We only support BLAKE3 for now
        let commitment = Blake3Commitment::new(encodings);
        let hash = *commitment.hash();

        let id = CommitmentId::new(self.merkle_leaves.len() as u32);

        let commitment: Commitment = commitment.into();

        // Store commitment with its id
        self.commitment_info
            .insert_no_overwrite(
                id,
                CommitmentInfo::new(commitment.kind(), ranges, direction),
            )
            .map_err(|(id, _)| CommitmentError::DuplicateCommitment(id))?;
        self.commitments.insert(id, commitment);

        // Insert commitment hash into the merkle tree
        self.merkle_leaves.push(hash);

        Ok(id)
    }

    /// Builds the [`SessionData`]
    pub fn build(self) -> Result<SessionData, SessionDataBuilderError> {
        let Self {
            handshake_data_decommitment,
            transcript_tx: tx_transcript,
            transcript_rx,
            merkle_leaves,
            commitments,
            commitment_info,
        } = self;

        let merkle_tree = MerkleTree::from_leaves(&merkle_leaves)?;

        Ok(SessionData {
            handshake_data_decommitment,
            tx_transcript,
            transcript_rx,
            merkle_tree,
            commitments,
            commitment_info,
        })
    }
}

/// Notarized session data.
///
/// This contains all the private data held by the `Prover` after notarization.
///
/// # Selective disclosure
///
/// The `Prover` can selectively disclose parts of the transcript to a `Verifier` using a
/// [`SubstringsProof`](crate::substrings::SubstringsProof).
///
/// See [`build_substrings_proof`](SessionData::build_substrings_proof).
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    tx_transcript: Transcript,
    transcript_rx: Transcript,
    merkle_tree: MerkleTree,
    /// Commitments to the transcript data.
    commitments: HashMap<CommitmentId, Commitment>,
    /// Info about the commitments.
    commitment_info: BiMap<CommitmentId, CommitmentInfo>,
}

opaque_debug::implement!(SessionData);

impl SessionData {
    /// Returns the decommitment to handshake data
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    /// Returns the transcript for data sent to the server
    pub fn sent_transcript(&self) -> &Transcript {
        &self.tx_transcript
    }

    /// Returns the transcript for data received from the server
    pub fn recv_transcript(&self) -> &Transcript {
        &self.transcript_rx
    }

    /// Returns the merkle tree for the prover's commitments
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// Returns a commitment if it exists.
    pub fn get_commitment(&self, id: &CommitmentId) -> Option<&Commitment> {
        self.commitments.get(id)
    }

    /// Returns the commitment id for a commitment with the given info, if it exists.
    pub fn get_commitment_id_by_info(
        &self,
        kind: CommitmentKind,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Option<CommitmentId> {
        self.commitment_info
            .get_by_right(&CommitmentInfo::new(kind, ranges, direction))
            .copied()
    }

    /// Returns commitment info, if it exists.
    pub fn get_commitment_info(&self, id: &CommitmentId) -> Option<&CommitmentInfo> {
        self.commitment_info.get_by_left(id)
    }

    /// Returns a substrings proof builder.
    pub fn build_substrings_proof(&self) -> SubstringsProofBuilder {
        SubstringsProofBuilder::new(self)
    }
}
