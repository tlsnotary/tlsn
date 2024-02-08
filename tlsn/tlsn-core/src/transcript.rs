//! Transcript data types.

use std::ops::Range;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utils::range::{RangeDifference, RangeSet, RangeUnion};

pub(crate) static TX_TRANSCRIPT_ID: &str = "tx";
pub(crate) static RX_TRANSCRIPT_ID: &str = "rx";

/// A transcript contains a subset of bytes from a TLS session
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Transcript {
    data: Bytes,
}

impl Transcript {
    /// Creates a new transcript with the given ID and data
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    /// Returns the actual traffic data of this transcript
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns a concatenated bytestring located in the given ranges of the transcript.
    ///
    /// # Panics
    ///
    /// Panics if the range set is empty or is out of bounds.
    pub(crate) fn get_bytes_in_ranges(&self, ranges: &RangeSet<usize>) -> Vec<u8> {
        let max = ranges.max().expect("range set is not empty");
        assert!(max <= self.data.len(), "range set is out of bounds");

        ranges
            .iter_ranges()
            .flat_map(|range| &self.data[range])
            .copied()
            .collect()
    }
}

/// A transcript which may have some data redacted.
#[derive(Debug)]
pub struct RedactedTranscript {
    data: Vec<u8>,
    /// Ranges of `data` which have been authenticated
    auth: RangeSet<usize>,
    /// Ranges of `data` which have been redacted
    redacted: RangeSet<usize>,
}

impl RedactedTranscript {
    /// Creates a new redacted transcript with the given length.
    ///
    /// All bytes in the transcript are initialized to 0.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the transcript
    /// * `slices` - A list of slices of data which have been authenticated
    pub fn new(len: usize, slices: Vec<TranscriptSlice>) -> Self {
        let mut data = vec![0u8; len];
        let mut auth = RangeSet::default();
        for slice in slices {
            data[slice.range()].copy_from_slice(slice.data());
            auth = auth.union(&slice.range());
        }
        let redacted = RangeSet::from(0..len).difference(&auth);

        Self {
            data,
            auth,
            redacted,
        }
    }

    /// Returns a reference to the data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [authed](RedactedTranscript::authed) for a set of ranges which have been.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns all the ranges of data which have been authenticated.
    pub fn authed(&self) -> &RangeSet<usize> {
        &self.auth
    }

    /// Returns all the ranges of data which have been redacted.
    pub fn redacted(&self) -> &RangeSet<usize> {
        &self.redacted
    }

    /// Sets all bytes in the transcript which were redacted.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the redacted bytes to
    pub fn set_redacted(&mut self, value: u8) {
        for range in self.redacted().clone().iter_ranges() {
            self.data[range].fill(value);
        }
    }

    /// Sets all bytes in the transcript which were redacted in the given range.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the redacted bytes to
    /// * `range` - The range of redacted bytes to set
    pub fn set_redacted_range(&mut self, value: u8, range: Range<usize>) {
        for range in self
            .redacted
            .difference(&(0..self.data.len()).difference(&range))
            .iter_ranges()
        {
            self.data[range].fill(value);
        }
    }
}

/// Slice of a transcript.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: Range<usize>,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    /// Creates a new transcript slice.
    pub fn new(range: Range<usize>, data: Vec<u8>) -> Self {
        Self { range, data }
    }

    /// Returns the range of bytes this slice refers to in the transcript
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Returns the bytes of this slice
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the bytes of this slice
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

/// The direction of data communicated over a TLS connection.
///
/// This is used to differentiate between data sent from the Prover to the TLS peer,
/// and data received by the Prover from the TLS peer (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    /// Sent from the Prover to the TLS peer.
    Sent,
    /// Received by the prover from the TLS peer.
    Received,
}

/// Returns the value ID for each byte in the provided range set
pub fn get_value_ids(
    ranges: &RangeSet<usize>,
    direction: Direction,
) -> impl Iterator<Item = String> + '_ {
    let id = match direction {
        Direction::Sent => TX_TRANSCRIPT_ID,
        Direction::Received => RX_TRANSCRIPT_ID,
    };

    ranges.iter().map(move |idx| format!("{}/{}", id, idx))
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn transcripts() -> (Transcript, Transcript) {
        let sent = "data sent 123456789".as_bytes().to_vec();
        let recv = "data received 987654321".as_bytes().to_vec();
        (Transcript::new(sent), Transcript::new(recv))
    }

    #[rstest]
    fn test_get_bytes_in_ranges(transcripts: (Transcript, Transcript)) {
        let (sent, recv) = transcripts;

        let range1 = Range { start: 2, end: 4 };
        let range2 = Range { start: 10, end: 15 };
        // a full range spanning the entirety of the data
        let range3 = Range {
            start: 0,
            end: sent.data().len(),
        };

        let expected = "ta12345".as_bytes().to_vec();
        assert_eq!(
            expected,
            sent.get_bytes_in_ranges(&RangeSet::from([range1.clone(), range2.clone()]))
        );

        let expected = "taved 9".as_bytes().to_vec();
        assert_eq!(
            expected,
            recv.get_bytes_in_ranges(&RangeSet::from([range1, range2]))
        );

        assert_eq!(
            sent.data().as_ref(),
            sent.get_bytes_in_ranges(&RangeSet::from([range3]))
        );
    }

    #[rstest]
    #[should_panic]
    fn test_get_bytes_in_ranges_empty(transcripts: (Transcript, Transcript)) {
        let (sent, _) = transcripts;
        sent.get_bytes_in_ranges(&RangeSet::default());
    }

    #[rstest]
    #[should_panic]
    fn test_get_bytes_in_ranges_out_of_bounds(transcripts: (Transcript, Transcript)) {
        let (sent, _) = transcripts;
        let range = Range {
            start: 0,
            end: sent.data().len() + 1,
        };
        sent.get_bytes_in_ranges(&RangeSet::from([range]));
    }
}
