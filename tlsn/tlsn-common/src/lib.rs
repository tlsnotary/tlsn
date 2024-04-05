//! Common code shared between `tlsn-prover` and `tlsn-verifier`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod attestation;
pub mod msg;
pub mod mux;
pub mod substring;
pub mod util;

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
pub enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
