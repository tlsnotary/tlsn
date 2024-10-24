//! Tools for selective disclosure of various formats.
//!
//! # Warning
//!
//! This library is not yet ready for production use, and should *NOT* be
//! considered secure.
//!
//! At present, this library does not verify that redacted data does not contain
//! control characters which can be used by a malicious prover to cheat.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod http;
pub mod json;

#[doc(hidden)]
pub use spansy;
pub use spansy::ParseError;
