//! Notary client library.
//!
//! This library contains TLSNotary notary client implementations, which helps to setup
//! connection to TLSN notary server via TCP or TLS, and subsequent requests for notarization

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod client;
mod error;

pub use client::{NotaryClient, NotaryConnection};
pub use error::ClientError;
