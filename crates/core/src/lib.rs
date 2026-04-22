//! TLSNotary core library.
//!
//! # Platform Support
//!
//! This crate depends on `rand`, which requires `getrandom` for OS-level
//! randomness. On targets where `getrandom` has no built-in backend (e.g.,
//! custom or embedded targets), set:
//!
//! ```text
//! RUSTFLAGS='--cfg getrandom_backend="unsupported"'
//! ```
//!
//! This allows compilation to succeed. Note that
//! [`Blinded::new`](hash::Blinded::new) requires a working RNG and will panic
//! on unsupported targets.

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

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerName,
    transcript::{PartialTranscript, TranscriptCommitment, TranscriptSecret},
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
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

opaque_debug::implement!(VerifierOutput);
