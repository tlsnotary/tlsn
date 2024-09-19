//! TLSNotary core library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod attestation;
pub mod connection;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub(crate) mod index;
pub(crate) mod merkle;
pub mod presentation;
mod provider;
pub mod request;
mod secrets;
pub(crate) mod serialize;
pub mod signing;
pub mod transcript;

pub use provider::CryptoProvider;
pub use secrets::Secrets;
