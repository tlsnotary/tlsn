//! TLSNotary core protocol library.
//!
//! This crate contains core types for the TLSNotary protocol, including some functionality for selective disclosure.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod commitment;
pub mod merkle;
pub mod msg;
pub mod proof;
pub mod session;
mod signature;
pub mod transcript;

pub use session::{HandshakeSummary, NotarizedSession, SessionData, SessionHeader, SessionProof};
pub use signature::Signature;
pub use transcript::{Direction, RedactedTranscript, Transcript, TranscriptSlice};

/// The maximum allowed total bytelength of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of plaintext encodings if the
/// commitment type is [crate::commitment::Blake3]).
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 << 31) - 1 by default)
const MAX_TOTAL_COMMITTED_DATA: usize = 1_000_000_000;

/// The encoding id
///
/// A 64 bit Blake3 hash which is used for the plaintext encodings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct EncodingId(u64);

impl EncodingId {
    /// Create a new encoding ID.
    pub(crate) fn new(id: &str) -> Self {
        let hash = mpz_core::utils::blake3(id.as_bytes());
        Self(u64::from_be_bytes(hash[..8].try_into().unwrap()))
    }

    /// Returns the encoding ID.
    pub fn to_inner(self) -> u64 {
        self.0
    }
}
