//! TLSNotary core protocol library.
//!
//! This crate contains core types for the TLSNotary protocol, including some functionality for selective disclosure.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

#[cfg(feature = "mpz")]
pub mod commitment;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
#[cfg(feature = "mpz")]
pub mod merkle;
pub mod msg;
#[cfg(feature = "mpz")]
pub mod proof;
#[cfg(feature = "mpz")]
pub mod session;
mod signature;
pub mod transcript;

#[cfg(feature = "mpz")]
pub use session::{HandshakeSummary, NotarizedSession, SessionData, SessionHeader};
pub use signature::{NotaryPublicKey, Signature};
#[cfg(feature = "tee")]
pub use msg::SignedSession;
#[cfg(feature = "mpz")]
pub use transcript::{Direction, RedactedTranscript, Transcript, TranscriptSlice};

#[cfg(feature = "mpz")]
use mpz_garble_core::{encoding_state, EncodedValue};
#[cfg(feature = "mpz")]
use serde::{Deserialize, Serialize};

/// The maximum allowed total bytelength of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of plaintext encodings if the
/// commitment type is [crate::commitment::Blake3]).
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 << 31) - 1 by default)
#[cfg(feature = "mpz")]
const MAX_TOTAL_COMMITTED_DATA: usize = 1_000_000_000;

/// A provider of plaintext encodings.
#[cfg(feature = "mpz")]
pub(crate) type EncodingProvider =
    Box<dyn Fn(&[&str]) -> Option<Vec<EncodedValue<encoding_state::Active>>> + Send>;

/// The encoding id
///
/// A 64 bit Blake3 hash which is used for the plaintext encodings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg(feature = "mpz")]
pub(crate) struct EncodingId(u64);

#[cfg(feature = "mpz")]
impl EncodingId {
    /// Create a new encoding ID.
    pub(crate) fn new(id: &str) -> Self {
        let hash = mpz_core::utils::blake3(id.as_bytes());
        Self(u64::from_be_bytes(hash[..8].try_into().unwrap()))
    }

    /// Returns the encoding ID.
    pub(crate) fn to_inner(self) -> u64 {
        self.0
    }
}

/// A Server's name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg(feature = "mpz")]
pub enum ServerName {
    /// A DNS name.
    Dns(String),
}

#[cfg(feature = "mpz")]
impl ServerName {
    /// Returns a reference to the server name as a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Dns(name) => name.as_str(),
        }
    }
}

#[cfg(feature = "mpz")]
impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        match self {
            Self::Dns(name) => name.as_ref(),
        }
    }
}
