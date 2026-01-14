//! TLSNotary library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod error;
pub(crate) mod ghash;
pub(crate) mod map;
pub(crate) mod mpz;
pub(crate) mod msg;
pub mod prover;
mod session;
pub(crate) mod tag;
pub(crate) mod transcript_internal;
pub mod verifier;

pub use error::Error;
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
