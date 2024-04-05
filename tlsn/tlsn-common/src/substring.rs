//! Substrings config types.

use tlsn_core::transcript::SubsequenceIdx;

/// Configuration for revealing substrings of the transcript.
pub struct SubstringsRevealConfig {
    seqs: Vec<SubsequenceIdx>,
}
