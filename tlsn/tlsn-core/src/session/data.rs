use crate::{
    commitment::TranscriptCommitments,
    proof::{SessionInfo, SubstringsProofBuilder},
    ServerName, Transcript,
};
use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

/// Session data used for notarization.
///
/// This contains all the private data held by the `Prover` after notarization including
/// commitments to the parts of the transcript.
///
/// # Selective disclosure
///
/// The `Prover` can selectively disclose parts of the transcript to a `Verifier` using a
/// [`SubstringsProof`](crate::proof::SubstringsProof).
///
/// See [`build_substrings_proof`](SessionData::build_substrings_proof).
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    session_info: SessionInfo,
    transcript_tx: Transcript,
    transcript_rx: Transcript,
    commitments: TranscriptCommitments,
}

impl SessionData {
    /// Creates new session data.
    pub fn new(
        server_name: ServerName,
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
        commitments: TranscriptCommitments,
    ) -> Self {
        let session_info = SessionInfo {
            server_name,
            handshake_decommitment: handshake_data_decommitment,
        };

        Self {
            session_info,
            transcript_tx,
            transcript_rx,
            commitments,
        }
    }

    /// Returns the session info
    pub fn session_info(&self) -> &SessionInfo {
        &self.session_info
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

opaque_debug::implement!(SessionData);
