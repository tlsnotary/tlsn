//! Notary client library.
//!
//! A notary client's purpose is to establish a connection to the notary server via TCP or TLS, and
//! to configure and request notarization.
//! Note that the actual notarization is not performed by the notary client but by the prover of the
//! TLSNotary protocol.
#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod client;
mod error;

pub use client::{Accepted, NotarizationRequest, NotaryClient, NotaryConnection};
pub use error::ClientError;
