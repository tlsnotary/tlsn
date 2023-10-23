//! The prover library
//!
//! This library contains TLSNotary prover implementations:
//!   * [`tls`] for the low-level API for working with the underlying byte streams of a TLS connection.
//!   * [`http`] for a higher-level API which provides abstractions for working with HTTP connections.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

#[cfg(feature = "formats")]
pub mod http;
pub mod tls;

use uid_mux::UidYamuxControl;
use utils_aio::codec::BincodeMux;

/// A muxer which uses Bincode for serialization, Yamux for multiplexing.
type Mux = BincodeMux<UidYamuxControl>;

use utils::range::{RangeSet, RangeUnion};

/// Collect ranges of transcripts
#[derive(Debug, Default)]
pub struct RangeCollector {
    reveal_sent: RangeSet<usize>,
    reveal_received: RangeSet<usize>,
}

impl RangeCollector {
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
