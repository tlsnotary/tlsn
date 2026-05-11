//! Platform-agnostic core SDK for TLSNotary.
//!
//! This crate provides the core SDK functionality that can be used across
//! different platforms (WASM, iOS, Android, native).
//!
//! # Architecture
//!
//! The SDK is built around the [`Io`] trait which abstracts bidirectional
//! byte streams. Platform-specific adapters implement this trait:
//!
//! - **WASM**: JavaScript-backed IO streams
//! - **iOS/Android**: FFI callback-based IO
//! - **Native**: Any `AsyncRead + AsyncWrite` stream
//!
//! # Example
//!
//! ```ignore
//! use tlsn_sdk_core::{SdkProver, ProverConfig, NetworkSetting};
//!
//! // Create prover with configuration.
//! let config = ProverConfig::builder("api.example.com")
//!     .max_sent_data(4096)
//!     .max_recv_data(16384)
//!     .network(NetworkSetting::Latency)
//!     .build();
//!
//! let mut prover = SdkProver::new(config)?;
//!
//! // Setup with verifier (IO stream provided by platform).
//! prover.setup(verifier_io).await?;
//!
//! // Send request through server connection.
//! let request = HttpRequest::get("/api/data")
//!     .header("Authorization", "Bearer token");
//! let response = prover.send_request_mpc(server_io, request).await?;
//!
//! // Get transcript and reveal data.
//! let transcript = prover.transcript()?;
//! prover.reveal(Reveal::new().recv(0..100).server_identity(true), None).await?;
//! ```

#![deny(missing_docs, unreachable_pub, unused_must_use, clippy::all)]

pub mod config;
pub mod error;
pub mod handler;
pub mod io;
pub mod logging;
pub mod prover;
mod spawn;
pub mod types;
pub mod verifier;

// Re-export main types for convenience.
pub use config::{NetworkSetting, ProverConfig, ProverMode, VerifierConfig};
pub use error::{Result, SdkError};
pub use handler::compute_reveal;
pub use io::{HyperIo, Io};
pub use prover::SdkProver;
pub use types::{
    Body, Commit, CommitRange, ConnectionInfo, Handler, HandlerAction, HandlerParams, HandlerPart,
    HandlerType, HashAlgorithm, HashOpening, HttpRequest, HttpResponse, Method, PartialTranscript,
    Reveal, RevealOutput, TlsVersion, Transcript, TranscriptLength, VerifierOutput,
};
pub use verifier::SdkVerifier;
