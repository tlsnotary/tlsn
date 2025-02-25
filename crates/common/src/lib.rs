//! Common code shared between `tlsn-prover` and `tlsn-verifier`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod commit;
pub mod config;
mod context;
pub mod msg;
pub mod mux;
pub mod transcript;
pub mod zk_aes;

pub use context::build_mt_context;

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
