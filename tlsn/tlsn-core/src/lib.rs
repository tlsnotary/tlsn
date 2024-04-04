//! TLSNotary core protocol library.
//!
//! This crate contains core types for the TLSNotary protocol, including some functionality for selective disclosure.

// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![forbid(unsafe_code)]

pub mod attestation;
pub mod conn;
pub mod encoding;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub(crate) mod merkle;
pub(crate) mod serialize;
mod signature;
pub mod substring;
pub mod transcript;

pub use signature::{NotaryPublicKey, Signature};
pub use transcript::{Direction, PartialTranscript, Transcript};

use conn::ServerIdentityProof;
use substring::SubstringsProof;

pub(crate) mod sealed {
    /// A sealed trait.
    pub trait Sealed {}
}

pub struct TlsProof {
    pub identity: ServerIdentityProof,
    pub substring: SubstringsProof,
}
