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

pub use mpz_memory_core::{binary::U8, Array};

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerName,
    transcript::{PartialTranscript, TranscriptCommitment, TranscriptSecret},
};

/// TLS session keys.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Client write IV.
    pub client_write_iv: Array<U8, 4>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Server write IV.
    pub server_write_iv: Array<U8, 4>,
    /// Server write MAC key.
    pub server_write_mac_key: Array<U8, 16>,
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
