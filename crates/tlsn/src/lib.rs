//! TLSNotary library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod commit;
pub mod config;
pub(crate) mod context;
pub(crate) mod ghash;
pub(crate) mod msg;
pub(crate) mod mux;
pub mod prover;
pub(crate) mod tag;
pub mod verifier;
pub(crate) mod zk_aes_ctr;

pub use tlsn_attestation as attestation;
pub use tlsn_core::{connection, hash, transcript};

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
