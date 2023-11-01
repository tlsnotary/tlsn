use crate::{
    commitment::TranscriptCommitments,
    proof::{substring::CommitmentProofBuilder, SessionInfo},
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
/// See [`build_substrings_proof`](NotarizationSessionData::build_substrings_proof).
#[derive(Serialize, Deserialize)]
pub struct NotarizationSessionData {
    session_data: SessionData,
    commitments: TranscriptCommitments,
}

impl NotarizationSessionData {
    /// Creates new session data.
    pub fn new(
        server_name: ServerName,
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
        commitments: TranscriptCommitments,
    ) -> Self {
        let session_data = SessionData::new(
            server_name,
            handshake_data_decommitment,
            transcript_tx,
            transcript_rx,
        );

        Self {
            session_data,
            commitments,
        }
    }

    /// Returns the session data
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }

    /// Returns the transcript for data sent to the server
    pub fn sent_transcript(&self) -> &Transcript {
        &self.session_data.transcript_tx
    }

    /// Returns the transcript for data received from the server
    pub fn recv_transcript(&self) -> &Transcript {
        &self.session_data.transcript_rx
    }

    /// Returns the transcript commitments.
    pub fn commitments(&self) -> &TranscriptCommitments {
        &self.commitments
    }

    /// Returns a substrings proof builder.
    pub fn build_substrings_proof(&self) -> CommitmentProofBuilder {
        CommitmentProofBuilder::new(
            &self.commitments,
            &self.session_data.transcript_tx,
            &self.session_data.transcript_rx,
        )
    }
}

opaque_debug::implement!(NotarizationSessionData);

/// Session data used when dealing with an app-specific verifier.
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    session_info: SessionInfo,
    transcript_tx: Transcript,
    transcript_rx: Transcript,
}

impl SessionData {
    /// Creates new session data.
    pub fn new(
        server_name: ServerName,
        handshake_data_decommitment: Decommitment<HandshakeData>,
        transcript_tx: Transcript,
        transcript_rx: Transcript,
    ) -> Self {
        let server_info = SessionInfo {
            server_name,
            handshake_data_decommitment,
        };

        SessionData {
            session_info: server_info,
            transcript_tx,
            transcript_rx,
        }
    }

    /// Returns the transcript for data sent to the server
    pub fn sent_transcript(&self) -> &Transcript {
        &self.transcript_tx
    }

    /// Returns the transcript for data received from the server
    pub fn recv_transcript(&self) -> &Transcript {
        &self.transcript_rx
    }

    /// Returns the [SessionInfo]
    pub fn session_info(&self) -> &SessionInfo {
        &self.session_info
    }
}

opaque_debug::implement!(SessionData);
