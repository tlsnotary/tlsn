use crate::{
    commitment::TranscriptCommitments, proof::SubstringsProofBuilder, ServerName, Transcript,
};
use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

/// Notarized session data.
///
/// This contains all the private data held by the `Prover` after notarization.
///
/// # Selective disclosure
///
/// The `Prover` can selectively disclose parts of the transcript to a `Verifier` using a
/// [`SubstringsProof`](crate::proof::SubstringsProof).
///
/// See [`build_substrings_proof`](SessionData::build_substrings_proof).
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    server_name: ServerName,
    handshake_data_decommitment: Decommitment<HandshakeData>,
    transcript_tx: Transcript,
    transcript_rx: Transcript,
    commitments: TranscriptCommitments,
}

opaque_debug::implement!(SessionData);

impl SessionData {
    /// Creates new session data.
    pub fn new(
        server_name: ServerName,
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
        commitments: TranscriptCommitments,
    ) -> Self {
        Self {
            server_name,
            handshake_data_decommitment,
            transcript_tx,
            transcript_rx,
            commitments,
        }
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the decommitment to handshake data
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.handshake_data_decommitment
    }

    /// Returns the transcript for data sent to the server
    pub fn sent_transcript(&self) -> &Transcript {
        &self.transcript_tx
    }

    /// Returns the transcript for data received from the server
    pub fn recv_transcript(&self) -> &Transcript {
        &self.transcript_rx
    }

    /// Returns the transcript commitments.
    pub fn commitments(&self) -> &TranscriptCommitments {
        &self.commitments
    }

    /// Returns a substrings proof builder.
    pub fn build_substrings_proof(&self) -> SubstringsProofBuilder {
        SubstringsProofBuilder::new(&self.commitments, &self.transcript_tx, &self.transcript_rx)
    }
}
