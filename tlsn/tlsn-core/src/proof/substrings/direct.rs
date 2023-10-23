//! Direct Substrings proofs.

use crate::{RedactedTranscript, Transcript};

/// A builder for substring proofs without commitments.
pub struct DirectSubstringsProofBuilder<'a> {
    transcript_tx: &'a Transcript,
    transcript_rx: &'a Transcript,
}

/// A substring proof without commitments
pub struct DirectSubstringsProof {}

impl DirectSubstringsProof {
    /// Verifies this proof and, if successful, returns the redacted sent and received transcripts.
    pub fn verify(&self) -> (RedactedTranscript, RedactedTranscript) {
        todo!()
    }
}
