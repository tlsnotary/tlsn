use crate::{
    commitment::TranscriptCommitments,
    proof::{ServerInfo, SubstringsProofBuilder},
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
    pub fn build_substrings_proof(&self) -> SubstringsProofBuilder {
        SubstringsProofBuilder::new(
            &self.commitments,
            &self.session_data.transcript_tx,
            &self.session_data.transcript_rx,
        )
    }
}

opaque_debug::implement!(NotarizationSessionData);

/// Session data.
///
/// This contains all the private data held by the `Prover` after finishing the TLSMPC.
///
/// # Selective disclosure
///
/// TODO: Add explanation...
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    server_info: ServerInfo,
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
        let server_info = ServerInfo {
            server_name,
            handshake_data_decommitment,
        };

        SessionData {
            server_info,
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

    /// Returns a proof of the TLS session
    pub fn server_info(&self) -> ServerInfo {
        self.server_info.clone()
    }

    /// Returns a substrings proof builder.
    pub fn build_substrings_proof(&self) -> () {
        // TODO: Create a substrings proof builder using `Decode` trait from DEAP VM
        todo!()
    }
}

opaque_debug::implement!(SessionData);
