//! The prover library.
//!
//! This library contains TLSNotary prover implementations:
//!   * [`tls`] for the low-level API for working with the underlying byte streams of a TLS connection.
//!   * [`http`] for a higher-level API which provides abstractions for working with HTTP connections.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

#[cfg(feature = "formats")]
pub mod http;
pub mod tls;
