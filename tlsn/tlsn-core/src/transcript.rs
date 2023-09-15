//! This module contains code for transcripts of the TLSNotary session

use std::ops::Range;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utils::range::{RangeDifference, RangeSet, RangeUnion};

/// An error related to transcripts
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    /// The provided ranges are not within the bounds of the transcript
    #[error("Ranges {0:?} are out of bounds")]
    RangesOutofBounds(RangeSet<usize>),
}

/// A transcript contains a subset of bytes from a TLS session
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Transcript {
    id: String,
    data: Bytes,
}

impl Transcript {
    /// Creates a new transcript with the given ID and data
    pub fn new(id: &str, data: impl Into<Bytes>) -> Self {
        Self {
            id: id.to_string(),
            data: data.into(),
        }
    }

    /// Returns the id used to identify this transcript
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Returns the actual traffic data of this transcript
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns the value ID for each byte in the provided range
    pub fn get_ids(&self, range: &RangeSet<usize>) -> Vec<String> {
        range
            .iter()
            .map(|idx| format!("{}/{}", self.id, idx))
            .collect::<Vec<_>>()
    }

    /// Returns a concatenated bytestring located in the given ranges of the transcript.
    ///
    /// Is only called with non-empty well-formed `ranges`
    pub(crate) fn get_bytes_in_ranges(
        &self,
        ranges: &RangeSet<usize>,
    ) -> Result<Vec<u8>, TranscriptError> {
        // all ranges must be within the bounds of the transcript
        if ranges.max().unwrap() > self.data.len() {
            return Err(TranscriptError::RangesOutofBounds(ranges.clone()));
        }

        Ok(ranges
            .iter_ranges()
            .flat_map(|range| &self.data[range])
            .copied()
            .collect())
    }
}

/// A transcript which may have some data redacted.
#[derive(Debug)]
pub struct RedactedTranscript {
    data: Vec<u8>,
    /// Ranges of data which have been authenticated
    auth: RangeSet<usize>,
    /// Ranges of data which have been redacted
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
    pub fn new(&mut self, len: usize, slices: Vec<TranscriptSlice>) -> Self {
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
}

/// Authenticated slice of [Transcript]. The [Direction] should be infered from some outer context.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: Range<usize>,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: Range<usize>, data: Vec<u8>) -> Self {
        Self { range, data }
    }

    /// Returns the range of bytes this slice refers to in the transcript
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Returns the actual traffic data of this slice
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A [Transcript] contains either a stream of bytes which were sent to the server
/// or a stream of bytes which were received from the server. The Prover creates
/// separate commitments to bytes in each direction.
pub enum Direction {
    /// Sent from the prover to the server
    Sent,
    /// Received by the prover from the server
    Received,
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn transcripts() -> (Transcript, Transcript) {
        let sent = "data sent 123456789".as_bytes().to_vec();
        let recv = "data received 987654321".as_bytes().to_vec();
        (Transcript::new("tx", sent), Transcript::new("rx", recv))
    }

    #[rstest]
    fn test_get_bytes_in_ranges_ok(transcripts: (Transcript, Transcript)) {
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
                .unwrap()
        );

        let expected = "taved 9".as_bytes().to_vec();
        assert_eq!(
            expected,
            recv.get_bytes_in_ranges(&RangeSet::from([range1, range2]))
                .unwrap()
        );

        assert_eq!(
            sent.data().as_ref(),
            sent.get_bytes_in_ranges(&RangeSet::from([range3])).unwrap()
        );
    }

    #[rstest]
    fn test_get_bytes_in_ranges_err(transcripts: (Transcript, Transcript)) {
        let (sent, _) = transcripts;

        // no_range provided
        let err = sent.get_bytes_in_ranges(&RangeSet::default());
        assert!(matches!(
            err.unwrap_err(),
            TranscriptError::RangesOutofBounds(_)
        ));

        // a range with the end bound larger than the data length
        let bad_range = Range {
            start: 2,
            end: (sent.data().len() + 1),
        };
        let err = sent.get_bytes_in_ranges(&RangeSet::from([bad_range]));
        assert!(matches!(
            err.unwrap_err(),
            TranscriptError::RangesOutofBounds(_)
        ));
    }
}
