//! TLSNotary library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod common;
pub mod prover;
pub mod verifier;

pub use tlsn_core::*;
