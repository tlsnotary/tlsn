//! TLSNotary protocol implementation.
//!
//! This crate provides the core protocol for generating and verifying proofs
//! of TLS sessions. A prover can demonstrate to a verifier that specific data
//! was exchanged with a TLS server, without revealing the full transcript.
//!
//! # Overview
//!
//! The protocol involves two parties:
//!
//! - **Prover** ([`Prover`](prover::Prover)): connects to a TLS server and
//!   generates proofs about the session.
//! - **Verifier** ([`Verifier`](verifier::Verifier)): collaborates with the
//!   prover during the TLS session and verifies the resulting proofs.
//!
//! Both parties communicate through an established [`Session`].
//!
//! # Workflow
//!
//! The protocol has two main phases:
//!
//! **Commitment**: The prover and verifier collaborate to construct a TLS
//! transcript commitment from the prover's communication with a TLS server.
//! This authenticates the transcript for the verifier, without the verifier
//! learning the contents.
//!
//! **Selective Disclosure**: The prover selectively reveals portions of the
//! committed transcript to the verifier, proving statements about the data
//! exchanged with the server.
//!
//! ## Steps
//!
//! 1. Establish a communication channel between prover and verifier.
//! 2. Create a [`Session`] on each side from the channel.
//! 3. Create a [`Prover`](prover::Prover) or [`Verifier`](verifier::Verifier).
//! 4. Run the commitment phase: the prover connects to the TLS server and
//!    exchanges data to obtain a commitment to the TLS transcript.
//! 5. (Optional) Perform selective disclosure: the prover provably reveals
//!    selected data to the verifier.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod deps;
mod error;
pub(crate) mod ghash;
pub(crate) mod map;
pub(crate) mod msg;
pub mod prover;
mod session;
pub(crate) mod tag;
pub(crate) mod transcript_internal;
pub mod verifier;

pub use error::Error;
pub use rangeset;
pub use session::{Session, SessionDriver, SessionHandle};
pub use tlsn_attestation as attestation;
pub use tlsn_core::{config, connection, hash, transcript, webpki};

/// Result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

use std::sync::LazyLock;

use semver::Version;

// Package version.
pub(crate) static VERSION: LazyLock<Version> = LazyLock::new(|| {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("cargo pkg version should be a valid semver")
});

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
