//! Different types of proofs used in the TLSNotary protocol.

mod session;
mod substrings;

pub use session::{default_cert_verifier, SessionInfo, SessionProof, SessionProofError};
pub use substrings::{
    SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError, SubstringsProofError,
};

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;
use utils::range::RangeSet;

use crate::Direction;

/// Proof that a transcript of communications took place between a Prover and Server.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizedTlsProof {
    /// Proof of the TLS handshake, server identity, and commitments to the transcript.
    pub session: SessionProof,
    /// Proof regarding the contents of the transcript.
    pub substrings: SubstringsProof,
}

/// Contains information about the TLS session between a Prover and a Server.
#[derive(Debug, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Information about the TLS session.
    pub session_info: SessionInfo,
    /// The length of the sent transcript.
    pub sent_len: usize,
    /// The length of the received transcript.
    pub recv_len: usize,
}

/// A trait that allows to build a substrings proof for a transcript
pub trait ProofBuilder<T: Sized>: Debug {
    /// Reveals the given range of bytes in the transcript.
    fn reveal(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut dyn ProofBuilder<T>, ProofBuilderError>;

    /// Builds the proof.
    fn build(self) -> Result<T, ProofBuilderError>;
}

/// The error type for proof builders.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProofBuilderError {
    #[error(transparent)]
    Commit(#[from] SubstringsProofBuilderError),
}
