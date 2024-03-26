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
pub mod transcript;

pub use signature::{NotaryPublicKey, Signature};
pub use transcript::{Direction, Slice, Transcript};

use serde::{Deserialize, Serialize};

/// A Server's name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServerName {
    /// A DNS name.
    Dns(String),
}

impl ServerName {
    /// Returns a reference to the server name as a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Dns(name) => name.as_str(),
        }
    }
}

impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        match self {
            Self::Dns(name) => name.as_ref(),
        }
    }
}

pub(crate) mod sealed {
    /// A sealed trait.
    pub trait Sealed {}
}
