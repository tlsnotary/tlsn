//! Transcript data types.

use std::ops::Range;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utils::range::{IndexRanges, RangeDifference, RangeSet, RangeUnion, ToRangeSet};

pub(crate) static TX_TRANSCRIPT_ID: &str = "tx";
pub(crate) static RX_TRANSCRIPT_ID: &str = "rx";

/// A transcript contains a subset of bytes from a TLS connection.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Transcript {
    data: Bytes,
}

impl Transcript {
    /// Creates a new transcript with the given ID and data
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    /// Returns the length of the transcript
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
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

        self.data.index_ranges(ranges)
    }
}

/// A partial transcript.
///
/// A partial transcript is a transcript which may not have all the data authenticated.
#[derive(Debug, Clone)]
pub struct PartialTranscript {
    data: Vec<u8>,
    /// Ranges of `data` which have been authenticated
    auth: RangeSet<usize>,
    /// Ranges of `data` which have not been authenticated
    unauth: RangeSet<usize>,
}

impl PartialTranscript {
    /// Creates a new partial transcript with the given length.
    ///
    /// All bytes in the transcript are initialized to 0.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the transcript
    /// * `slices` - A list of slices of data which have been authenticated
    pub fn new(len: usize, slices: Vec<Slice>) -> Self {
        let mut data = vec![0u8; len];
        let mut auth = RangeSet::default();
        for slice in slices {
            data[slice.idx.range.clone()].copy_from_slice(&slice.data);
            auth = auth.union(&slice.idx.range);
        }
        let redacted = RangeSet::from(0..len).difference(&auth);

        Self {
            data,
            auth,
            unauth: redacted,
        }
    }

    /// Returns whether the transcript is complete.
    pub fn is_complete(&self) -> bool {
        self.auth.len() == self.data.len()
    }

    /// Returns the length of the transcript.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns a reference to the data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [authed](PartialTranscript::authed) for a set of ranges which have been.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns all the ranges of data which have been authenticated.
    pub fn authed(&self) -> &RangeSet<usize> {
        &self.auth
    }

    /// Returns all the ranges of data which haven't been authenticated.
    pub fn unauthed(&self) -> &RangeSet<usize> {
        &self.unauth
    }

    /// Unions the authenticated data of this transcript with another.
    ///
    /// # Panics
    ///
    /// Panics if the other transcript is not the same length.
    pub(crate) fn union(&mut self, other: &PartialTranscript) {
        assert_eq!(
            self.data.len(),
            other.data.len(),
            "transcripts are not the same length"
        );

        for range in other.auth.difference(&self.auth).iter_ranges() {
            self.data[range.clone()].copy_from_slice(&other.data[range]);
        }
        self.auth = self.auth.union(&other.auth);
        self.unauth = RangeSet::from(0..self.data.len()).difference(&self.auth);
    }

    /// Sets all bytes in the transcript which haven't been authenticated.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the unauthenticated bytes to
    pub fn set_unauthed(&mut self, value: u8) {
        for range in self.unauthed().clone().iter_ranges() {
            self.data[range].fill(value);
        }
    }

    /// Sets all bytes in the transcript which haven't been authenticated within the given range.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the unauthenticated bytes to
    /// * `range` - The range of bytes to set
    pub fn set_unauthed_range(&mut self, value: u8, range: Range<usize>) {
        for range in self
            .unauth
            .difference(&(0..self.data.len()).difference(&range))
            .iter_ranges()
        {
            self.data[range].fill(value);
        }
    }
}

/// The direction of data communicated over a TLS connection.
///
/// This is used to differentiate between data sent from the Prover to the TLS peer,
/// and data received by the Prover from the TLS peer (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    /// Sent from the Prover to the TLS peer.
    Sent = 0x00,
    /// Received by the prover from the TLS peer.
    Received = 0x01,
}

/// A slice index of a transcript.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SliceIdx {
    /// The direction of the transcript.
    pub direction: Direction,
    /// The range of the transcript.
    pub range: Range<usize>,
}

/// Slice of a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    idx: SliceIdx,
    data: Vec<u8>,
}

impl Slice {
    pub(crate) fn new(idx: SliceIdx, data: Vec<u8>) -> Self {
        assert_eq!(
            idx.range.len(),
            data.len(),
            "data length does not match range length"
        );

        Self { idx, data }
    }

    /// Returns the index of the slice.
    pub fn index(&self) -> &SliceIdx {
        &self.idx
    }

    /// Returns the data of the slice.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Returns the slice as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Into<Vec<u8>> for Slice {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

/// A transcript subsequence index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubsequenceIdx {
    /// The direction of the transcript.
    pub direction: Direction,
    /// The ranges of the transcript.
    pub ranges: RangeSet<usize>,
}

/// A transcript subsequence.
pub struct Subsequence {
    /// The index of the subsequence.
    pub idx: SubsequenceIdx,
    /// The data of the subsequence.
    pub data: Vec<u8>,
}

impl Subsequence {
    /// Converts the subsequence into slices.
    pub fn into_slices(self) -> Vec<Slice> {
        let mut slices = Vec::with_capacity(self.idx.ranges.len_ranges());
        let mut ranges = self.idx.ranges.into_inner();

        // Reverse the ranges so we can split them off from the end.
        ranges.reverse();

        let mut data = self.data;
        for range in ranges {
            let slice = data.split_off(data.len() - range.len());
            slices.push(Slice::new(
                SliceIdx {
                    direction: self.idx.direction,
                    range,
                },
                slice,
            ));
        }

        // Reverse the slices so they are in ascending order.
        slices.reverse();
        slices
    }
}

/// A type which can commit to subsequences of a transcript.
pub trait TranscriptCommit {
    /// The error type of the committer.
    type Error;

    /// Commits the given ranges of the sent data transcript.
    fn commit_sent(&mut self, ranges: &dyn ToRangeSet<usize>) -> Result<&mut Self, Self::Error> {
        self.commit(ranges, Direction::Sent)
    }

    /// Commits the given ranges of the received data transcript.
    fn commit_recv(&mut self, ranges: &dyn ToRangeSet<usize>) -> Result<&mut Self, Self::Error> {
        self.commit(ranges, Direction::Received)
    }

    /// Commits the given ranges of the transcript.
    fn commit(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, Self::Error>;
}

/// A type which can reveal subsequences of a transcript.
pub trait TranscriptReveal {
    /// The error type of the revealer.
    type Error;

    /// Reveals the given ranges of the sent data transcript.
    fn reveal_sent(&mut self, ranges: &dyn ToRangeSet<usize>) -> Result<&mut Self, Self::Error> {
        self.reveal(ranges, Direction::Sent)
    }

    /// Reveals the given ranges of the received data transcript.
    fn reveal_recv(&mut self, ranges: &dyn ToRangeSet<usize>) -> Result<&mut Self, Self::Error> {
        self.reveal(ranges, Direction::Received)
    }

    /// Reveals the given ranges of the transcript.
    fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, Self::Error>;
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

    #[test]
    fn test_subsequence_into_slices() {
        let seq = Subsequence {
            idx: SubsequenceIdx {
                direction: Direction::Sent,
                ranges: RangeSet::from([0..1, 2..4, 5..6]),
            },
            data: vec![0, 2, 3, 5],
        };

        let slices = seq.into_slices();
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[0].as_bytes(), &[0]);
        assert_eq!(slices[1].as_bytes(), &[2, 3]);
        assert_eq!(slices[2].as_bytes(), &[5]);
    }
}
