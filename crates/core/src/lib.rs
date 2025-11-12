//! TLSNotary core library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod connection;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub mod merkle;
pub mod transcript;
pub mod webpki;
pub use rangeset;
pub mod config;
pub(crate) mod display;
//pub mod grammar;
pub mod json;
pub mod predicates;

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerName,
    transcript::{
        encoding::EncoderSecret, PartialTranscript, TranscriptCommitment, TranscriptSecret,
    },
};

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
    /// Encoding commitment secret.
    pub encoder_secret: Option<EncoderSecret>,
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

opaque_debug::implement!(VerifierOutput);
