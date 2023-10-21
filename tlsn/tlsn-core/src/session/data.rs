use crate::{
    commitment::TranscriptCommitments, proof::SubstringsProofBuilder, ServerName, Transcript,
};
use mpz_core::commit::Decommitment;
use serde::{Deserialize, Serialize};
use tls_core::handshake::HandshakeData;

/// Notarized session data.
///
/// This contains all the private data held by the `Prover` after notarization including
/// commitments to the parts of the transcript.
///
/// # Selective disclosure
///
/// The `Prover` can selectively disclose parts of the transcript to a `Verifier` using a
/// [`SubstringsProof`](crate::proof::SubstringsProof).
///
/// See [`build_substrings_proof`](NotarizeSessionData::build_substrings_proof).
#[derive(Serialize, Deserialize)]
pub struct NotarizedSessionData {
    session_data: SessionData,
    commitments: TranscriptCommitments,
}

impl NotarizedSessionData {
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

    /// Returns the server name.
    pub fn server_name(&self) -> &ServerName {
        &self.session_data.server_name
    }

    /// Returns the decommitment to handshake data
    pub fn handshake_data_decommitment(&self) -> &Decommitment<HandshakeData> {
        &self.session_data.handshake_data_decommitment
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

opaque_debug::implement!(NotarizedSessionData);

/// Session data.
///
/// This contains all the private data held by the `Prover` after finishing the TLSMPC.
///
/// # Selective disclosure
///
/// TODO: Add explanation...
#[derive(Serialize, Deserialize)]
pub struct SessionData {
    server_name: ServerName,
    handshake_data_decommitment: Decommitment<HandshakeData>,
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
        SessionData {
            server_name,
            handshake_data_decommitment,
            transcript_tx,
            transcript_rx,
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

    /// Returns a substrings proof builder.
    pub fn build_substrings_proof(&self) -> () {
        // TODO: Create a substrings proof builder using `Decode` trait from DEAP VM
        todo!()
    }
}

opaque_debug::implement!(SessionData);
