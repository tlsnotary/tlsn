//! Transcript data types.

use std::ops::Range;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utils::range::{IndexRanges, RangeDifference, RangeSet, RangeUnion};

use crate::conn::TranscriptLength;

/// Sent data transcript ID.
pub static TX_TRANSCRIPT_ID: &str = "tx";
/// Received data transcript ID.
pub static RX_TRANSCRIPT_ID: &str = "rx";

/// A transcript contains all the data communicated over a TLS connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transcript {
    /// Data sent from the Prover to the Server.
    sent: Bytes,
    /// Data received by the Prover from the Server.
    received: Bytes,
}

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

    /// Returns a slice of the transcript in the given range if it is in bounds, otherwise `None`.
    pub fn get_slice(&self, idx: &SliceIdx) -> Option<&[u8]> {
        let data = match idx.direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.received,
        };

        if idx.range.end > data.len() {
            return None;
        }

        data.get(idx.range.clone())
    }

    /// Returns the bytes in the given ranges if they are in bounds, otherwise `None`.
    pub fn get_subsequence(&self, idx: &SubsequenceIdx) -> Option<Vec<u8>> {
        let data = match idx.direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.received,
        };

        let end = idx.ranges.end()?;
        if end > data.len() {
            return None;
        }

        Some(data.index_ranges(&idx.ranges))
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
    pub(crate) fn new(sent_len: usize, received_len: usize) -> Self {
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

    /// Returns whether the index is in bounds of the transcript.
    pub fn contains(&self, idx: &SliceIdx) -> bool {
        match idx.direction {
            Direction::Sent => idx.range.end <= self.sent.len(),
            Direction::Received => idx.range.end <= self.received.len(),
        }
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
    pub(crate) fn union(&mut self, other: &PartialTranscript) {
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
    pub(crate) fn union_subsequence(&mut self, seq: &Subsequence) {
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
    pub fn set_unauthed_range(&mut self, value: u8, idx: &SliceIdx) {
        match idx.direction {
            Direction::Sent => {
                for range in idx.range.difference(&self.sent_authed).iter_ranges() {
                    self.sent[range].fill(value);
                }
            }
            Direction::Received => {
                for range in idx.range.difference(&self.received_authed).iter_ranges() {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subsequence {
    /// The index of the subsequence.
    pub idx: SubsequenceIdx,
    /// The data of the subsequence.
    pub data: Vec<u8>,
}

impl Subsequence {
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

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn transcript() -> Transcript {
        Transcript::new(b"data sent 123456789", b"data received 987654321")
    }

    #[rstest]
    fn test_get_slice(transcript: Transcript) {
        let slice = transcript
            .get_slice(&SliceIdx {
                direction: Direction::Sent,
                range: 0..4,
            })
            .unwrap();
        assert_eq!(slice, b"data");

        let slice = transcript
            .get_slice(&SliceIdx {
                direction: Direction::Received,
                range: 0..4,
            })
            .unwrap();
        assert_eq!(slice, b"data");

        let slice = transcript
            .get_slice(&SliceIdx {
                direction: Direction::Sent,
                range: 7..10,
            })
            .unwrap();
        assert_eq!(slice, b"123");

        let slice = transcript
            .get_slice(&SliceIdx {
                direction: Direction::Received,
                range: 9..12,
            })
            .unwrap();
        assert_eq!(slice, b"987");

        let slice = transcript.get_slice(&SliceIdx {
            direction: Direction::Sent,
            range: 0..0,
        });
        assert_eq!(slice, None);

        let slice = transcript.get_slice(&SliceIdx {
            direction: Direction::Sent,
            range: 0..transcript.sent().len() + 1,
        });
        assert_eq!(slice, None);
    }

    #[rstest]
    fn test_get_subsequence(transcript: Transcript) {
        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Sent,
            ranges: RangeSet::from([0..4, 7..10]),
        });
        assert_eq!(subseq, Some(b"data123".to_vec()));

        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Received,
            ranges: RangeSet::from([0..4, 9..12]),
        });
        assert_eq!(subseq, Some(b"data987".to_vec()));

        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Sent,
            ranges: RangeSet::from([0..4, 7..10, 11..12]),
        });
        assert_eq!(subseq, None);

        let subseq = transcript.get_subsequence(&SubsequenceIdx {
            direction: Direction::Sent,
            ranges: RangeSet::from([0..4, 7..10, 11..13]),
        });
        assert_eq!(subseq, None);
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
