//! Different types of proofs used in the TLSNotary protocol.

mod session;
pub mod substring;

pub use session::{default_cert_verifier, SessionInfo, SessionProof, SessionProofError};
pub use substring::{SubstringProofBuilder, SubstringProofBuilderError, SubstringProofError};

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use substring::CommitmentProof;

/// Proof that a transcript of communications took place between a Prover and Server.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizedTlsProof {
    /// Proof of the TLS handshake, server identity, and commitments to the transcript.
    pub session: SessionProof,
    /// Proof regarding the contents of the transcript.
    pub substrings: CommitmentProof,
}
