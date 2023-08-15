//! This crate contains types used by the Prover, the Notary, and the Verifier

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod commitment;
mod error;
#[cfg(any(test, feature = "fixtures"))]
#[allow(missing_docs)]
pub mod fixtures;
mod handshake_summary;
pub(crate) mod inclusion_proof;
pub mod merkle;
pub mod msg;
mod session;
pub mod signature;
pub mod substrings;
pub mod transcript;
mod utils;

pub use commitment::Commitment;
pub use error::Error;
pub use handshake_summary::HandshakeSummary;
pub use inclusion_proof::InclusionProof;
pub use session::{NotarizedSession, SessionArtifacts, SessionData, SessionHeader, SessionProof};
pub use substrings::{
    commitment::{SubstringsCommitment, SubstringsCommitmentSet},
    opening::SubstringsOpeningSet,
};
pub use transcript::{Direction, Transcript, TranscriptSlice};

/// The maximum allowed total bytelength of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of plaintext encodings if the
/// commitment type is [crate::commitment::Blake3]).
///
/// This value must not exceed bcs's MAX_SEQUENCE_LENGTH limit (which is (1 << 31) - 1 by default)
const MAX_TOTAL_COMMITTED_DATA: u64 = 1_000_000_000;

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
