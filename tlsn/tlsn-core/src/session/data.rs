use std::collections::HashMap;

use crate::{
    commitment::{
        Blake3, CommitmentId, TranscriptCommitment, TranscriptCommitmentDetails,
        TranscriptCommitmentKind,
    },
    merkle::{MerkleError, MerkleTree},
    substrings::proof::SubstringsProofBuilder,
    Direction, SubstringsCommitment, SubstringsCommitmentSet, Transcript,
};
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::Hash,
};
use mpz_garble_core::{encoding_state, EncodedValue};
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;
use utils::range::RangeSet;

/// A builder for [`SessionData`]
pub struct SessionDataBuilder {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    tx_transcript: Transcript,
    rx_transcript: Transcript,
    merkle_leaves: Vec<Hash>,
    commitment_details: HashMap<CommitmentId, TranscriptCommitmentDetails>,
    commitments: HashMap<CommitmentId, TranscriptCommitment>,
}

/// An error for [`SessionDataBuilder`]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SessionDataBuilderError(String);

impl From<MerkleError> for SessionDataBuilderError {
    fn from(e: MerkleError) -> Self {
        Self(format!("merkle error: {}", e))
    }
}

opaque_debug::implement!(SessionDataBuilder);

impl SessionDataBuilder {
    /// Creates a new builder
    pub fn new(
        handshake_data_decommitment: Decommitment<HandshakeData>,
        tx_transcript: Transcript,
        rx_transcript: Transcript,
    ) -> Self {
        Self {
            handshake_data_decommitment,
            tx_transcript,
            rx_transcript,
            merkle_leaves: Vec::default(),
            commitment_details: HashMap::default(),
            commitments: HashMap::default(),
        }
    }

    /// Returns a reference to the sent data transcript.
    pub fn sent_transcript(&self) -> &Transcript {
        &self.tx_transcript
    }

    /// Returns a reference to the received data transcript.
    pub fn recv_transcript(&self) -> &Transcript {
        &self.rx_transcript
    }

    /// Add a commitment to substrings of the transcript
    pub fn add_substrings_commitment(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
        encodings: &[EncodedValue<encoding_state::Active>],
    ) -> Result<CommitmentId, SessionDataBuilderError> {
        if ranges.len() != encodings.len() {
            return Err(SessionDataBuilderError(format!(
                "ranges and encodings must have the same length: {} != {}",
                ranges.len(),
                encodings.len()
            )));
        }

        let (decommitment, hash) = encodings.hash_commit();

        let id = CommitmentId::new(self.merkle_leaves.len() as u32);

        // Insert commitment into the merkle tree
        self.merkle_leaves.push(hash);

        let commitment = SubstringsCommitment::new(
            id,
            Blake3::new(hash).into(),
            ranges.clone(),
            direction,
            *decommitment.nonce(),
        );

        // Store commitment details
        self.commitment_details.insert(
            id,
            TranscriptCommitmentDetails::new(
                ranges,
                direction,
                TranscriptCommitmentKind::Substrings,
            ),
        );

        // Store commitment with its id
        self.commitments
            .insert(id, TranscriptCommitment::Substrings(commitment));

        Ok(id)
    }

    /// Builds the [`SessionData`]
    pub fn build(self) -> Result<SessionData, SessionDataBuilderError> {
        let Self {
            handshake_data_decommitment,
            tx_transcript,
            rx_transcript,
            merkle_leaves,
            commitment_details,
            commitments,
        } = self;

        let merkle_tree = MerkleTree::from_leaves(&merkle_leaves)?;

        Ok(SessionData {
            handshake_data_decommitment,
            tx_transcript,
            rx_transcript,
            merkle_tree,
            commitment_details,
            commitments,
        })
    }
}

/// Wrapper for various data associated with the TLSNotary session
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    handshake_data_decommitment: Decommitment<HandshakeData>,
    tx_transcript: Transcript,
    rx_transcript: Transcript,
    merkle_tree: MerkleTree,
    commitment_details: HashMap<CommitmentId, TranscriptCommitmentDetails>,
    commitments: HashMap<CommitmentId, TranscriptCommitment>,
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
        &self.rx_transcript
    }

    /// Returns the merkle tree for the prover's commitments
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// The prover's commitments to substrings of the transcript
    pub fn commitments(&self) -> &HashMap<CommitmentId, TranscriptCommitment> {
        &self.commitments
    }

    /// Returns a [`SubstringsProof`] builder.
    pub fn build_substrings_proof(&self) -> SubstringsProofBuilder {
        SubstringsProofBuilder::new(self)
    }
}
