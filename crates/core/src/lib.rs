//! TLSNotary core library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub mod merkle;
pub mod transcript;
pub mod webpki;

use serde::{Deserialize, Serialize};

use crate::{
    connection::{HandshakeData, ServerName},
    transcript::{
        PartialTranscript, TranscriptCommitRequest, TranscriptCommitment, TranscriptSecret,
    },
};

/// Payload sent to the verifier.
#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvePayload {
    /// Handshake data.
    pub handshake: Option<(ServerName, HandshakeData)>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitment configuration.
    pub transcript_commit: Option<TranscriptCommitRequest>,
}

/// Prover output.
#[derive(Serialize, Deserialize)]
pub struct ProverOutput {
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
    /// Transcript commitment secrets.
    pub transcript_secrets: Vec<TranscriptSecret>,
}

opaque_debug::implement!(ProverOutput);

/// Verifier output.
#[derive(Serialize, Deserialize)]
pub struct VerifierOutput {
    /// Server identity.
    pub server_name: Option<ServerName>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

opaque_debug::implement!(VerifierOutput);
