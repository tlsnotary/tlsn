//! Direct Substrings proofs.

use utils::range::{RangeSet, RangeUnion};

/// A builder for substring proofs without commitments.
#[derive(Debug, Default)]
pub struct DirectSubstringsProofBuilder {
    reveal_sent: RangeSet<usize>,
    reveal_received: RangeSet<usize>,
}

impl DirectSubstringsProofBuilder {
    /// Marks the given range of the sent transcript to be revealed.
    pub fn add_reveal_sent(&mut self, range: impl Into<RangeSet<usize>>) {
        self.reveal_sent = self.reveal_sent.union(&range.into());
    }

    /// Marks the given range of the received transcript to be revealed.
    pub fn add_reveal_received(&mut self, range: impl Into<RangeSet<usize>>) {
        self.reveal_received = self.reveal_received.union(&range.into());
    }

    /// Builds the redacted transcripts.
    pub fn build(self) -> (RangeSet<usize>, RangeSet<usize>) {
        (self.reveal_sent, self.reveal_received)
    }
}
