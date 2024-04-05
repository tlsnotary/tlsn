//! Transcript data types.

use std::ops::Range;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utils::range::{IndexRanges, RangeDifference, RangeSet, RangeUnion};

use crate::{conn::TranscriptLength, serialize::CanonicalSerialize};

pub use validation::{InvalidSubsequence, InvalidSubsequenceIdx};

/// Sent data transcript ID.
pub static TX_TRANSCRIPT_ID: &str = "tx";
/// Received data transcript ID.
pub static RX_TRANSCRIPT_ID: &str = "rx";

/// A transcript contains all the data communicated over a TLS connection.
#[derive(Clone, Serialize, Deserialize)]
pub struct Transcript {
    /// Data sent from the Prover to the Server.
    sent: Bytes,
    /// Data received by the Prover from the Server.
    received: Bytes,
}

opaque_debug::implement!(Transcript);

impl Transcript {
    /// Creates a new transcript.
    pub fn new(sent: impl Into<Vec<u8>>, received: impl Into<Vec<u8>>) -> Self {
        Self {
            sent: Bytes::from(sent.into()),
            received: Bytes::from(received.into()),
        }
    }

    /// Returns a reference to the sent data.
    pub fn sent(&self) -> &Bytes {
        &self.sent
    }

    /// Returns a reference to the received data.
    pub fn received(&self) -> &Bytes {
        &self.received
    }

    /// Returns the length of the sent and received data, respectively.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> (usize, usize) {
        (self.sent.len(), self.received.len())
    }

    /// Returns the length of the transcript in the given direction.
    pub(crate) fn len_of_direction(&self, direction: Direction) -> usize {
        match direction {
            Direction::Sent => self.sent.len(),
            Direction::Received => self.received.len(),
        }
    }

    /// Returns the transcript length.
    pub fn length(&self) -> TranscriptLength {
        TranscriptLength {
            sent: self.sent.len() as u32,
            received: self.received.len() as u32,
        }
    }

    /// Returns the bytes in the given ranges if they are in bounds, otherwise `None`.
    pub fn get_subsequence(&self, idx: &SubsequenceIdx) -> Option<Subsequence> {
        let data = match idx.direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.received,
        };

        if idx.end() > data.len() {
            return None;
        }

        Some(
            Subsequence::new(idx.clone(), data.index_ranges(&idx.ranges))
                .expect("data is same length as index"),
        )
    }
}

/// A partial transcript.
///
/// A partial transcript is a transcript which may not have all the data authenticated.
#[derive(Debug, Clone)]
pub struct PartialTranscript {
    /// Data sent from the Prover to the Server.
    sent: Vec<u8>,
    /// Data received by the Prover from the Server.
    received: Vec<u8>,

    /// Ranges of `sent` which have been authenticated.
    sent_authed: RangeSet<usize>,
    /// Ranges of `received` which have been authenticated.
    received_authed: RangeSet<usize>,
}

impl PartialTranscript {
    /// Creates a new partial transcript initalized to all 0s.
    ///
    /// # Arguments
    ///
    /// * `sent_len` - The length of the sent data.
    /// * `received_len` - The length of the received data.
    pub fn new(sent_len: usize, received_len: usize) -> Self {
        Self {
            sent: vec![0; sent_len],
            received: vec![0; received_len],
            sent_authed: RangeSet::default(),
            received_authed: RangeSet::default(),
        }
    }

    /// Returns whether the transcript is complete.
    pub fn is_complete(&self) -> bool {
        self.sent_authed.len() == self.sent.len()
            && self.received_authed.len() == self.received.len()
    }

    /// Returns whether the subsequence index is in bounds of the transcript.
    pub fn contains_subsequence(&self, idx: &SubsequenceIdx) -> bool {
        match idx.direction {
            Direction::Sent => {
                if let Some(end) = idx.ranges.end() {
                    end <= self.sent.len()
                } else {
                    false
                }
            }
            Direction::Received => {
                if let Some(end) = idx.ranges.end() {
                    end <= self.received.len()
                } else {
                    false
                }
            }
        }
    }

    /// Returns a reference to the sent data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [sent_authed](PartialTranscript::sent_authed) for a set of ranges which have been.
    pub fn sent_unsafe(&self) -> &[u8] {
        &self.sent
    }

    /// Returns a reference to the received data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [received_authed](PartialTranscript::received_authed) for a set of ranges which have been.
    pub fn received_unsafe(&self) -> &[u8] {
        &self.received
    }

    /// Returns all the ranges of the sent data which have been authenticated.
    pub fn sent_authed(&self) -> &RangeSet<usize> {
        &self.sent_authed
    }

    /// Returns all the ranges of the received data which have been authenticated.
    pub fn received_authed(&self) -> &RangeSet<usize> {
        &self.received_authed
    }

    /// Returns all the ranges of the sent data which haven't been authenticated.
    pub fn sent_unauthed(&self) -> RangeSet<usize> {
        RangeSet::from(0..self.sent.len()).difference(&self.sent_authed)
    }

    /// Returns all the ranges of the received data which haven't been authenticated.
    pub fn received_unauthed(&self) -> RangeSet<usize> {
        RangeSet::from(0..self.received.len()).difference(&self.received_authed)
    }

    /// Unions the authenticated data of this transcript with another.
    ///
    /// # Panics
    ///
    /// Panics if the other transcript is not the same length.
    pub fn union_transcript(&mut self, other: &PartialTranscript) {
        assert_eq!(
            self.sent.len(),
            other.sent.len(),
            "sent data are not the same length"
        );
        assert_eq!(
            self.received.len(),
            other.received.len(),
            "received data are not the same length"
        );

        for range in other
            .sent_authed
            .difference(&self.sent_authed)
            .iter_ranges()
        {
            self.sent[range.clone()].copy_from_slice(&other.sent[range]);
        }

        for range in other
            .received_authed
            .difference(&self.received_authed)
            .iter_ranges()
        {
            self.received[range.clone()].copy_from_slice(&other.received[range]);
        }

        self.sent_authed = self.sent_authed.union(&other.sent_authed);
        self.received_authed = self.received_authed.union(&other.received_authed);
    }

    /// Unions an authenticated subsequence into this transcript.
    ///
    /// # Panics
    ///
    /// Panics if the subsequence is outside the bounds of the transcript.
    pub fn union_subsequence(&mut self, seq: &Subsequence) {
        match seq.idx.direction {
            Direction::Sent => {
                seq.copy_to(&mut self.sent);
                self.sent_authed = self.sent_authed.union(&seq.idx.ranges);
            }
            Direction::Received => {
                seq.copy_to(&mut self.received);
                self.received_authed = self.received_authed.union(&seq.idx.ranges);
            }
        }
    }

    /// Sets all bytes in the transcript which haven't been authenticated.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the unauthenticated bytes to
    pub fn set_unauthed(&mut self, value: u8) {
        for range in self.sent_unauthed().iter_ranges() {
            self.sent[range].fill(value);
        }
        for range in self.received_unauthed().iter_ranges() {
            self.received[range].fill(value);
        }
    }

    /// Sets all bytes in the transcript which haven't been authenticated within the given range.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the unauthenticated bytes to
    /// * `range` - The range of bytes to set
    pub fn set_unauthed_range(&mut self, value: u8, direction: Direction, range: Range<usize>) {
        match direction {
            Direction::Sent => {
                for range in range.difference(&self.sent_authed).iter_ranges() {
                    self.sent[range].fill(value);
                }
            }
            Direction::Received => {
                for range in range.difference(&self.received_authed).iter_ranges() {
                    self.received[range].fill(value);
                }
            }
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

/// A transcript subsequence index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "validation::SubsequenceIdxUnchecked")]
pub struct SubsequenceIdx {
    /// The direction of the transcript.
    direction: Direction,
    /// The ranges of the transcript.
    ranges: RangeSet<usize>,
}

impl SubsequenceIdx {
    /// Creates a new subsequence index.
    pub fn new(
        direction: Direction,
        ranges: impl Into<RangeSet<usize>>,
    ) -> Result<Self, InvalidSubsequenceIdx> {
        Self::validate(Self {
            direction,
            ranges: ranges.into(),
        })
    }

    /// Returns the start of the index.
    pub fn start(&self) -> usize {
        self.ranges.min().expect("index can not be empty")
    }

    /// Returns the end of the index, non-inclusive.
    pub fn end(&self) -> usize {
        self.ranges.end().expect("index can not be empty")
    }

    /// Returns the direction of the index.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the ranges of the index.
    pub fn ranges(&self) -> &RangeSet<usize> {
        &self.ranges
    }

    /// Returns the length of the index.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

impl CanonicalSerialize for SubsequenceIdx {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self { direction, ranges } = self;

        let mut bytes = Vec::new();
        bytes.push(*direction as u8);
        bytes.extend_from_slice(&(ranges.len_ranges() as u32).to_le_bytes());
        for range in ranges.iter_ranges() {
            bytes.extend_from_slice(&(range.start as u32).to_le_bytes());
            bytes.extend_from_slice(&(range.end as u32).to_le_bytes());
        }
        bytes
    }
}

/// A transcript subsequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "validation::SubsequenceUnchecked")]
pub struct Subsequence {
    /// The index of the subsequence.
    idx: SubsequenceIdx,
    /// The data of the subsequence.
    data: Vec<u8>,
}

impl Subsequence {
    /// Creates a new subsequence.
    pub fn new(idx: SubsequenceIdx, data: Vec<u8>) -> Result<Self, InvalidSubsequence> {
        Self::validate(Self { idx, data })
    }

    /// Returns the index of the subsequence.
    pub fn index(&self) -> &SubsequenceIdx {
        &self.idx
    }

    /// Returns the data of the subsequence.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the subsequence.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns the inner parts of the subsequence.
    pub fn into_parts(self) -> (SubsequenceIdx, Vec<u8>) {
        (self.idx, self.data)
    }

    /// Copies the subsequence data into the given destination.
    ///
    /// # Panics
    ///
    /// Panics if the subsequence ranges are out of bounds.
    pub(crate) fn copy_to(&self, dest: &mut [u8]) {
        let mut offset = 0;
        for range in self.idx.ranges.iter_ranges() {
            dest[range.clone()].copy_from_slice(&self.data[offset..offset + range.len()]);
            offset += range.len();
        }
    }
}

mod validation {
    use super::*;

    /// Invalid subsequence index error.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid subsequence index: {0}")]
    pub struct InvalidSubsequenceIdx(&'static str);

    impl SubsequenceIdx {
        pub(crate) fn validate(self) -> Result<Self, InvalidSubsequenceIdx> {
            if self.ranges.is_empty() {
                return Err(InvalidSubsequenceIdx("subsequence index can not be empty"));
            }

            Ok(self)
        }
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct SubsequenceIdxUnchecked {
        direction: Direction,
        ranges: RangeSet<usize>,
    }

    impl TryFrom<SubsequenceIdxUnchecked> for SubsequenceIdx {
        type Error = InvalidSubsequenceIdx;

        fn try_from(unchecked: SubsequenceIdxUnchecked) -> Result<Self, Self::Error> {
            Self::new(unchecked.direction, unchecked.ranges)
        }
    }

    /// Invalid subsequence error.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid subsequence: {0}")]
    pub struct InvalidSubsequence(&'static str);

    impl Subsequence {
        pub(crate) fn validate(self) -> Result<Self, InvalidSubsequence> {
            if self.idx.ranges.len() != self.data.len() {
                return Err(InvalidSubsequence(
                    "index length does not match data length",
                ));
            }

            if self.data.is_empty() {
                return Err(InvalidSubsequence("subsequence can not be empty"));
            }

            Ok(self)
        }
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct SubsequenceUnchecked {
        idx: SubsequenceIdx,
        data: Vec<u8>,
    }

    impl TryFrom<SubsequenceUnchecked> for Subsequence {
        type Error = InvalidSubsequence;

        fn try_from(unchecked: SubsequenceUnchecked) -> Result<Self, Self::Error> {
            Self::new(unchecked.idx, unchecked.data)
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn transcript() -> Transcript {
        Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        )
    }

    #[rstest]
    fn test_get_subsequence(transcript: Transcript) {
        let subseq = transcript
            .get_subsequence(&SubsequenceIdx {
                direction: Direction::Sent,
                ranges: RangeSet::from([0..4, 7..10]),
            })
            .unwrap();
        assert_eq!(subseq.data, vec![0, 1, 2, 3, 7, 8, 9]);

        let subseq = transcript
            .get_subsequence(&SubsequenceIdx {
                direction: Direction::Received,
                ranges: RangeSet::from([0..4, 9..12]),
            })
            .unwrap();
        assert_eq!(subseq.data, vec![0, 1, 2, 3, 9, 10, 11]);

        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Sent,
            ranges: RangeSet::from([0..4, 7..10, 11..13]),
        });
        assert_eq!(subseq, None);

        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Sent,
            ranges: RangeSet::from([0..4, 7..10, 11..13]),
        });
        assert_eq!(subseq, None);
    }
}
