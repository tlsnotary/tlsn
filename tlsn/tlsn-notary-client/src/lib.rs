//! Notary client library.
//!
//! This library contains TLSNotary notary client implementations, which helps to setup prover that
//! connects to TLSN notary server via TCP or TLS

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod client;
pub mod error;
