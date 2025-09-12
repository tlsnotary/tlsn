//! Transcript types.
//!
//! All application data communicated over a TLS connection is referred to as a
//! [`Transcript`]. A transcript is essentially just two vectors of bytes, each
//! corresponding to a [`Direction`].
//!
//! TLS operates over a bidirectional byte stream, and thus there are no
//! application layer semantics present in the transcript. For example, HTTPS is
//! an application layer protocol that runs *over TLS* so there is no concept of
//! "requests" or "responses" in the transcript itself. These semantics must be
//! recovered by parsing the application data and relating it to the bytes
//! in the transcript.
//!
//! ## Selective Disclosure
//!
//! Using a [`TranscriptProof`] a Prover can selectively disclose parts of a
//! transcript to a Verifier in the form of a [`PartialTranscript`]. A Verifier
//! always learns the length of the transcript, but sensitive data can be
//! withheld.

mod commit;
pub mod encoding;
pub mod hash;
mod proof;
mod tls;

use std::{fmt, ops::Range};

use rangeset::{Difference, IndexRanges, RangeSet, Union};
use serde::{Deserialize, Serialize};

use crate::connection::TranscriptLength;

pub use commit::{
    TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitConfigBuilderError,
    TranscriptCommitRequest, TranscriptCommitment, TranscriptCommitmentKind, TranscriptSecret,
};
pub use proof::{
    TranscriptProof, TranscriptProofBuilder, TranscriptProofBuilderError, TranscriptProofError,
};
pub use tls::{Record, TlsTranscript};
pub use tls_core::msgs::enums::ContentType;

/// A transcript contains the plaintext of all application data communicated
/// between the Prover and the Server.
#[derive(Clone, Serialize, Deserialize)]
pub struct Transcript {
    /// Data sent from the Prover to the Server.
    sent: Vec<u8>,
    /// Data received by the Prover from the Server.
    received: Vec<u8>,
}

opaque_debug::implement!(Transcript);

impl Transcript {
    /// Creates a new transcript.
    pub fn new(sent: impl Into<Vec<u8>>, received: impl Into<Vec<u8>>) -> Self {
        Self {
            sent: sent.into(),
            received: received.into(),
        }
    }

    /// Returns a reference to the sent data.
    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

    /// Returns a reference to the received data.
    pub fn received(&self) -> &[u8] {
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

    /// Returns the subsequence of the transcript with the provided index,
    /// returning `None` if the index is out of bounds.
    pub fn get(&self, direction: Direction, idx: &RangeSet<usize>) -> Option<Subsequence> {
        let data = match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.received,
        };

        if idx.end().unwrap_or(0) > data.len() {
            return None;
        }

        Some(
            Subsequence::new(idx.clone(), data.index_ranges(idx))
                .expect("data is same length as index"),
        )
    }

    /// Returns a partial transcript containing the provided indices.
    ///
    /// # Panics
    ///
    /// Panics if the indices are out of bounds.
    ///
    /// # Arguments
    ///
    /// * `sent_idx` - The indices of the sent data to include.
    /// * `recv_idx` - The indices of the received data to include.
    pub fn to_partial(
        &self,
        sent_idx: RangeSet<usize>,
        recv_idx: RangeSet<usize>,
    ) -> PartialTranscript {
        let mut sent = vec![0; self.sent.len()];
        let mut received = vec![0; self.received.len()];

        for range in sent_idx.iter_ranges() {
            sent[range.clone()].copy_from_slice(&self.sent[range]);
        }

        for range in recv_idx.iter_ranges() {
            received[range.clone()].copy_from_slice(&self.received[range]);
        }

        PartialTranscript {
            sent,
            received,
            sent_authed_idx: sent_idx,
            received_authed_idx: recv_idx,
        }
    }
}

/// A partial transcript.
///
/// A partial transcript is a transcript which may not have all the data
/// authenticated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "CompressedPartialTranscript")]
#[serde(into = "CompressedPartialTranscript")]
#[cfg_attr(test, derive(PartialEq))]
pub struct PartialTranscript {
    /// Data sent from the Prover to the Server.
    sent: Vec<u8>,
    /// Data received by the Prover from the Server.
    received: Vec<u8>,
    /// Index of `sent` which have been authenticated.
    sent_authed_idx: RangeSet<usize>,
    /// Index of `received` which have been authenticated.
    received_authed_idx: RangeSet<usize>,
}

/// `PartialTranscript` in a compressed form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "validation::CompressedPartialTranscriptUnchecked")]
pub struct CompressedPartialTranscript {
    /// Sent data which has been authenticated.
    sent_authed: Vec<u8>,
    /// Received data which has been authenticated.
    received_authed: Vec<u8>,
    /// Index of `sent_authed`.
    sent_idx: RangeSet<usize>,
    /// Index of `received_authed`.
    recv_idx: RangeSet<usize>,
    /// Total bytelength of sent data in the original partial transcript.
    sent_total: usize,
    /// Total bytelength of received data in the original partial transcript.
    recv_total: usize,
}

impl From<PartialTranscript> for CompressedPartialTranscript {
    fn from(uncompressed: PartialTranscript) -> Self {
        Self {
            sent_authed: uncompressed
                .sent
                .index_ranges(&uncompressed.sent_authed_idx),
            received_authed: uncompressed
                .received
                .index_ranges(&uncompressed.received_authed_idx),
            sent_idx: uncompressed.sent_authed_idx,
            recv_idx: uncompressed.received_authed_idx,
            sent_total: uncompressed.sent.len(),
            recv_total: uncompressed.received.len(),
        }
    }
}

impl From<CompressedPartialTranscript> for PartialTranscript {
    fn from(compressed: CompressedPartialTranscript) -> Self {
        let mut sent = vec![0; compressed.sent_total];
        let mut received = vec![0; compressed.recv_total];

        let mut offset = 0;

        for range in compressed.sent_idx.iter_ranges() {
            sent[range.clone()]
                .copy_from_slice(&compressed.sent_authed[offset..offset + range.len()]);
            offset += range.len();
        }

        let mut offset = 0;

        for range in compressed.recv_idx.iter_ranges() {
            received[range.clone()]
                .copy_from_slice(&compressed.received_authed[offset..offset + range.len()]);
            offset += range.len();
        }

        Self {
            sent,
            received,
            sent_authed_idx: compressed.sent_idx,
            received_authed_idx: compressed.recv_idx,
        }
    }
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
            sent_authed_idx: RangeSet::default(),
            received_authed_idx: RangeSet::default(),
        }
    }

    /// Returns the length of the sent transcript.
    pub fn len_sent(&self) -> usize {
        self.sent.len()
    }

    /// Returns the length of the received transcript.
    pub fn len_received(&self) -> usize {
        self.received.len()
    }

    /// Returns whether the transcript is complete.
    pub fn is_complete(&self) -> bool {
        self.sent_authed_idx.len() == self.sent.len()
            && self.received_authed_idx.len() == self.received.len()
    }

    /// Returns whether the index is in bounds of the transcript.
    pub fn contains(&self, direction: Direction, idx: &RangeSet<usize>) -> bool {
        match direction {
            Direction::Sent => idx.end().unwrap_or(0) <= self.sent.len(),
            Direction::Received => idx.end().unwrap_or(0) <= self.received.len(),
        }
    }

    /// Returns a reference to the sent data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [sent_authed](PartialTranscript::sent_authed) for a set of ranges which
    /// have been.
    pub fn sent_unsafe(&self) -> &[u8] {
        &self.sent
    }

    /// Returns a reference to the received data.
    ///
    /// # Warning
    ///
    /// Not all of the data in the transcript may have been authenticated. See
    /// [received_authed](PartialTranscript::received_authed) for a set of
    /// ranges which have been.
    pub fn received_unsafe(&self) -> &[u8] {
        &self.received
    }

    /// Returns the index of sent data which have been authenticated.
    pub fn sent_authed(&self) -> &RangeSet<usize> {
        &self.sent_authed_idx
    }

    /// Returns the index of received data which have been authenticated.
    pub fn received_authed(&self) -> &RangeSet<usize> {
        &self.received_authed_idx
    }

    /// Returns the index of sent data which haven't been authenticated.
    pub fn sent_unauthed(&self) -> RangeSet<usize> {
        (0..self.sent.len()).difference(&self.sent_authed_idx)
    }

    /// Returns the index of received data which haven't been authenticated.
    pub fn received_unauthed(&self) -> RangeSet<usize> {
        (0..self.received.len()).difference(&self.received_authed_idx)
    }

    /// Returns an iterator over the authenticated data in the transcript.
    pub fn iter(&self, direction: Direction) -> impl Iterator<Item = u8> + '_ {
        let (data, authed) = match direction {
            Direction::Sent => (&self.sent, &self.sent_authed_idx),
            Direction::Received => (&self.received, &self.received_authed_idx),
        };

        authed.iter().map(|i| data[i])
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
            .sent_authed_idx
            .difference(&self.sent_authed_idx)
            .iter_ranges()
        {
            self.sent[range.clone()].copy_from_slice(&other.sent[range]);
        }

        for range in other
            .received_authed_idx
            .difference(&self.received_authed_idx)
            .iter_ranges()
        {
            self.received[range.clone()].copy_from_slice(&other.received[range]);
        }

        self.sent_authed_idx = self.sent_authed_idx.union(&other.sent_authed_idx);
        self.received_authed_idx = self.received_authed_idx.union(&other.received_authed_idx);
    }

    /// Unions an authenticated subsequence into this transcript.
    ///
    /// # Panics
    ///
    /// Panics if the subsequence is outside the bounds of the transcript.
    pub fn union_subsequence(&mut self, direction: Direction, seq: &Subsequence) {
        match direction {
            Direction::Sent => {
                seq.copy_to(&mut self.sent);
                self.sent_authed_idx = self.sent_authed_idx.union(&seq.idx);
            }
            Direction::Received => {
                seq.copy_to(&mut self.received);
                self.received_authed_idx = self.received_authed_idx.union(&seq.idx);
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

    /// Sets all bytes in the transcript which haven't been authenticated within
    /// the given range.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to set the unauthenticated bytes to
    /// * `range` - The range of bytes to set
    pub fn set_unauthed_range(&mut self, value: u8, direction: Direction, range: Range<usize>) {
        match direction {
            Direction::Sent => {
                for range in range.difference(&self.sent_authed_idx).iter_ranges() {
                    self.sent[range].fill(value);
                }
            }
            Direction::Received => {
                for range in range.difference(&self.received_authed_idx).iter_ranges() {
                    self.received[range].fill(value);
                }
            }
        }
    }
}

/// The direction of data communicated over a TLS connection.
///
/// This is used to differentiate between data sent from the Prover to the TLS
/// peer, and data received by the Prover from the TLS peer (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    /// Sent from the Prover to the TLS peer.
    Sent = 0x00,
    /// Received by the prover from the TLS peer.
    Received = 0x01,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Sent => write!(f, "sent"),
            Direction::Received => write!(f, "received"),
        }
    }
}

/// Transcript subsequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "validation::SubsequenceUnchecked")]
pub struct Subsequence {
    /// Index of the subsequence.
    idx: RangeSet<usize>,
    /// Data of the subsequence.
    data: Vec<u8>,
}

impl Subsequence {
    /// Creates a new subsequence.
    pub fn new(idx: RangeSet<usize>, data: Vec<u8>) -> Result<Self, InvalidSubsequence> {
        if idx.len() != data.len() {
            return Err(InvalidSubsequence(
                "index length does not match data length",
            ));
        }

        Ok(Self { idx, data })
    }

    /// Returns the index of the subsequence.
    pub fn index(&self) -> &RangeSet<usize> {
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
    pub fn into_parts(self) -> (RangeSet<usize>, Vec<u8>) {
        (self.idx, self.data)
    }

    /// Copies the subsequence data into the given destination.
    ///
    /// # Panics
    ///
    /// Panics if the subsequence ranges are out of bounds.
    pub(crate) fn copy_to(&self, dest: &mut [u8]) {
        let mut offset = 0;
        for range in self.idx.iter_ranges() {
            dest[range.clone()].copy_from_slice(&self.data[offset..offset + range.len()]);
            offset += range.len();
        }
    }
}

/// Invalid subsequence error.
#[derive(Debug, thiserror::Error)]
#[error("invalid subsequence: {0}")]
pub struct InvalidSubsequence(&'static str);

mod validation {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(super) struct SubsequenceUnchecked {
        idx: RangeSet<usize>,
        data: Vec<u8>,
    }

    impl TryFrom<SubsequenceUnchecked> for Subsequence {
        type Error = InvalidSubsequence;

        fn try_from(unchecked: SubsequenceUnchecked) -> Result<Self, Self::Error> {
            Self::new(unchecked.idx, unchecked.data)
        }
    }

    /// Invalid compressed partial transcript error.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid compressed partial transcript: {0}")]
    pub struct InvalidCompressedPartialTranscript(&'static str);

    #[derive(Debug, Deserialize)]
    #[cfg_attr(test, derive(Serialize))]
    pub(super) struct CompressedPartialTranscriptUnchecked {
        sent_authed: Vec<u8>,
        received_authed: Vec<u8>,
        sent_idx: RangeSet<usize>,
        recv_idx: RangeSet<usize>,
        sent_total: usize,
        recv_total: usize,
    }

    impl TryFrom<CompressedPartialTranscriptUnchecked> for CompressedPartialTranscript {
        type Error = InvalidCompressedPartialTranscript;

        fn try_from(unchecked: CompressedPartialTranscriptUnchecked) -> Result<Self, Self::Error> {
            if unchecked.sent_authed.len() != unchecked.sent_idx.len()
                || unchecked.received_authed.len() != unchecked.recv_idx.len()
            {
                return Err(InvalidCompressedPartialTranscript(
                    "lengths of index and data don't match",
                ));
            }

            if unchecked.sent_idx.end().unwrap_or(0) > unchecked.sent_total
                || unchecked.recv_idx.end().unwrap_or(0) > unchecked.recv_total
            {
                return Err(InvalidCompressedPartialTranscript(
                    "ranges are not in bounds of the data",
                ));
            }

            Ok(Self {
                received_authed: unchecked.received_authed,
                recv_idx: unchecked.recv_idx,
                recv_total: unchecked.recv_total,
                sent_authed: unchecked.sent_authed,
                sent_idx: unchecked.sent_idx,
                sent_total: unchecked.sent_total,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use rstest::{fixture, rstest};

        use super::*;

        #[fixture]
        fn partial_transcript() -> CompressedPartialTranscriptUnchecked {
            CompressedPartialTranscriptUnchecked {
                received_authed: vec![1, 2, 3, 11, 12, 13],
                sent_authed: vec![4, 5, 6, 14, 15, 16],
                recv_idx: RangeSet::from([1..4, 11..14]),
                sent_idx: RangeSet::from([4..7, 14..17]),
                sent_total: 20,
                recv_total: 20,
            }
        }

        #[rstest]
        fn test_partial_transcript_valid(partial_transcript: CompressedPartialTranscriptUnchecked) {
            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<CompressedPartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_ok());
        }

        #[rstest]
        // Expect to fail since the length of data and the length of the index do not
        // match.
        fn test_partial_transcript_invalid_lengths(
            mut partial_transcript: CompressedPartialTranscriptUnchecked,
        ) {
            // Add an extra byte to the data.
            let mut old = partial_transcript.sent_authed;
            old.extend([1]);
            partial_transcript.sent_authed = old;

            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<CompressedPartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_err());
        }

        #[rstest]
        // Expect to fail since the index is out of bounds.
        fn test_partial_transcript_invalid_ranges(
            mut partial_transcript: CompressedPartialTranscriptUnchecked,
        ) {
            // Change the total to be less than the last range's end bound.
            let end = partial_transcript
                .sent_idx
                .iter_ranges()
                .next_back()
                .unwrap()
                .end;

            partial_transcript.sent_total = end - 1;

            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<CompressedPartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_err());
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

    #[fixture]
    fn partial_transcript() -> PartialTranscript {
        transcript().to_partial(RangeSet::from([1..4, 6..9]), RangeSet::from([2..5, 7..10]))
    }

    #[rstest]
    fn test_transcript_get_subsequence(transcript: Transcript) {
        let subseq = transcript
            .get(Direction::Received, &RangeSet::from([0..4, 7..10]))
            .unwrap();
        assert_eq!(subseq.data, vec![0, 1, 2, 3, 7, 8, 9]);

        let subseq = transcript
            .get(Direction::Sent, &RangeSet::from([0..4, 9..12]))
            .unwrap();
        assert_eq!(subseq.data, vec![0, 1, 2, 3, 9, 10, 11]);

        let subseq = transcript.get(Direction::Received, &RangeSet::from([0..4, 7..10, 11..13]));
        assert_eq!(subseq, None);

        let subseq = transcript.get(Direction::Sent, &RangeSet::from([0..4, 7..10, 11..13]));
        assert_eq!(subseq, None);
    }

    #[rstest]
    fn test_partial_transcript_serialization_ok(partial_transcript: PartialTranscript) {
        let bytes = bincode::serialize(&partial_transcript).unwrap();
        let deserialized_transcript: PartialTranscript = bincode::deserialize(&bytes).unwrap();
        assert_eq!(partial_transcript, deserialized_transcript);
    }

    #[rstest]
    fn test_transcript_to_partial_success(transcript: Transcript) {
        let partial = transcript.to_partial(RangeSet::from(0..2), RangeSet::from(3..7));
        assert_eq!(partial.sent_unsafe(), [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            partial.received_unsafe(),
            [0, 0, 0, 3, 4, 5, 6, 0, 0, 0, 0, 0]
        );
    }

    #[rstest]
    #[should_panic]
    fn test_transcript_to_partial_failure(transcript: Transcript) {
        let _ = transcript.to_partial(RangeSet::from(0..14), RangeSet::from(3..7));
    }

    #[rstest]
    fn test_partial_transcript_contains(transcript: Transcript) {
        let partial = transcript.to_partial(RangeSet::from(0..2), RangeSet::from(3..7));
        assert!(partial.contains(Direction::Sent, &RangeSet::from([0..5, 7..10])));
        assert!(!partial.contains(Direction::Received, &RangeSet::from([4..6, 7..13])))
    }

    #[rstest]
    fn test_partial_transcript_unauthed(transcript: Transcript) {
        let partial = transcript.to_partial(RangeSet::from(0..2), RangeSet::from(3..7));
        assert_eq!(partial.sent_unauthed(), RangeSet::from(2..12));
        assert_eq!(partial.received_unauthed(), RangeSet::from([0..3, 7..12]));
    }

    #[rstest]
    fn test_partial_transcript_union_success(transcript: Transcript) {
        // Non overlapping ranges.
        let mut simple_partial = transcript.to_partial(RangeSet::from(0..2), RangeSet::from(3..7));

        let other_simple_partial =
            transcript.to_partial(RangeSet::from(3..5), RangeSet::from(1..2));

        simple_partial.union_transcript(&other_simple_partial);

        assert_eq!(
            simple_partial.sent_unsafe(),
            [0, 1, 0, 3, 4, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            simple_partial.received_unsafe(),
            [0, 1, 0, 3, 4, 5, 6, 0, 0, 0, 0, 0]
        );
        assert_eq!(simple_partial.sent_authed(), &RangeSet::from([0..2, 3..5]));
        assert_eq!(
            simple_partial.received_authed(),
            &RangeSet::from([1..2, 3..7])
        );

        // Overwrite with another partial transcript.

        let another_simple_partial =
            transcript.to_partial(RangeSet::from(1..4), RangeSet::from(6..9));

        simple_partial.union_transcript(&another_simple_partial);

        assert_eq!(
            simple_partial.sent_unsafe(),
            [0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            simple_partial.received_unsafe(),
            [0, 1, 0, 3, 4, 5, 6, 7, 8, 0, 0, 0]
        );
        assert_eq!(simple_partial.sent_authed(), &RangeSet::from(0..5));
        assert_eq!(
            simple_partial.received_authed(),
            &RangeSet::from([1..2, 3..9])
        );

        // Overlapping ranges.
        let mut overlap_partial = transcript.to_partial(RangeSet::from(4..6), RangeSet::from(3..7));

        let other_overlap_partial =
            transcript.to_partial(RangeSet::from(3..5), RangeSet::from(5..9));

        overlap_partial.union_transcript(&other_overlap_partial);

        assert_eq!(
            overlap_partial.sent_unsafe(),
            [0, 0, 0, 3, 4, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            overlap_partial.received_unsafe(),
            [0, 0, 0, 3, 4, 5, 6, 7, 8, 0, 0, 0]
        );
        assert_eq!(overlap_partial.sent_authed(), &RangeSet::from([3..5, 4..6]));
        assert_eq!(
            overlap_partial.received_authed(),
            &RangeSet::from([3..7, 5..9])
        );

        // Equal ranges.
        let mut equal_partial = transcript.to_partial(RangeSet::from(4..6), RangeSet::from(3..7));

        let other_equal_partial = transcript.to_partial(RangeSet::from(4..6), RangeSet::from(3..7));

        equal_partial.union_transcript(&other_equal_partial);

        assert_eq!(
            equal_partial.sent_unsafe(),
            [0, 0, 0, 0, 4, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            equal_partial.received_unsafe(),
            [0, 0, 0, 3, 4, 5, 6, 0, 0, 0, 0, 0]
        );
        assert_eq!(equal_partial.sent_authed(), &RangeSet::from(4..6));
        assert_eq!(equal_partial.received_authed(), &RangeSet::from(3..7));

        // Subset ranges.
        let mut subset_partial =
            transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));

        let other_subset_partial =
            transcript.to_partial(RangeSet::from(6..9), RangeSet::from(5..6));

        subset_partial.union_transcript(&other_subset_partial);

        assert_eq!(
            subset_partial.sent_unsafe(),
            [0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 0, 0]
        );
        assert_eq!(
            subset_partial.received_unsafe(),
            [0, 0, 0, 3, 4, 5, 6, 7, 8, 9, 10, 0]
        );
        assert_eq!(subset_partial.sent_authed(), &RangeSet::from(4..10));
        assert_eq!(subset_partial.received_authed(), &RangeSet::from(3..11));
    }

    #[rstest]
    #[should_panic]
    fn test_partial_transcript_union_failure(transcript: Transcript) {
        let mut partial = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));

        let other_transcript = Transcript::new(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        );

        let other_partial = other_transcript.to_partial(RangeSet::from(6..9), RangeSet::from(5..6));

        partial.union_transcript(&other_partial);
    }

    #[rstest]
    fn test_partial_transcript_union_subseq_success(transcript: Transcript) {
        let mut partial = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));
        let sent_seq =
            Subsequence::new(RangeSet::from([0..3, 5..7]), [0, 1, 2, 5, 6].into()).unwrap();
        let recv_seq =
            Subsequence::new(RangeSet::from([0..4, 5..7]), [0, 1, 2, 3, 5, 6].into()).unwrap();

        partial.union_subsequence(Direction::Sent, &sent_seq);
        partial.union_subsequence(Direction::Received, &recv_seq);

        assert_eq!(partial.sent_unsafe(), [0, 1, 2, 0, 4, 5, 6, 7, 8, 9, 0, 0]);
        assert_eq!(
            partial.received_unsafe(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0]
        );
        assert_eq!(partial.sent_authed(), &RangeSet::from([0..3, 4..10]));
        assert_eq!(partial.received_authed(), &RangeSet::from(0..11));

        // Overwrite with another subseq.
        let other_sent_seq = Subsequence::new(RangeSet::from(0..3), [3, 2, 1].into()).unwrap();

        partial.union_subsequence(Direction::Sent, &other_sent_seq);
        assert_eq!(partial.sent_unsafe(), [3, 2, 1, 0, 4, 5, 6, 7, 8, 9, 0, 0]);
        assert_eq!(partial.sent_authed(), &RangeSet::from([0..3, 4..10]));
    }

    #[rstest]
    #[should_panic]
    fn test_partial_transcript_union_subseq_failure(transcript: Transcript) {
        let mut partial = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));

        let sent_seq =
            Subsequence::new(RangeSet::from([0..3, 13..15]), [0, 1, 2, 5, 6].into()).unwrap();

        partial.union_subsequence(Direction::Sent, &sent_seq);
    }

    #[rstest]
    fn test_partial_transcript_set_unauthed_range(transcript: Transcript) {
        let mut partial = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..7));

        partial.set_unauthed_range(7, Direction::Sent, 2..5);
        partial.set_unauthed_range(5, Direction::Sent, 0..2);
        partial.set_unauthed_range(3, Direction::Received, 4..6);
        partial.set_unauthed_range(1, Direction::Received, 3..7);

        assert_eq!(partial.sent_unsafe(), [5, 5, 7, 7, 4, 5, 6, 7, 8, 9, 0, 0]);
        assert_eq!(
            partial.received_unsafe(),
            [0, 0, 0, 3, 4, 5, 6, 0, 0, 0, 0, 0]
        );
    }

    #[rstest]
    #[should_panic]
    fn test_subsequence_new_invalid_len() {
        let _ = Subsequence::new(RangeSet::from([0..3, 5..8]), [0, 1, 2, 5, 6].into()).unwrap();
    }

    #[rstest]
    #[should_panic]
    fn test_subsequence_copy_to_invalid_len() {
        let seq = Subsequence::new(RangeSet::from([0..3, 5..7]), [0, 1, 2, 5, 6].into()).unwrap();

        let mut data: [u8; 3] = [0, 1, 2];
        seq.copy_to(&mut data);
    }
}
