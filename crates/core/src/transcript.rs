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
pub mod hash;
mod proof;
#[cfg(test)]
pub(crate) mod test;
mod tls;

use std::{fmt, ops::Range};

use rangeset::{
    iter::RangeIterator,
    ops::{Index, Set},
    set::RangeSet,
};
use serde::{Deserialize, Serialize};

use crate::connection::TranscriptLength;

pub use commit::{
    TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitConfigBuilderError,
    TranscriptCommitRequest, TranscriptCommitment, TranscriptCommitmentKind, TranscriptSecret,
};
pub use proof::{
    TranscriptProof, TranscriptProofBuilder, TranscriptProofBuilderError, TranscriptProofError,
};
pub use tls::{ContentType, Record, TlsTranscript, TlsTranscriptBuilder, TlsTranscriptError};

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
            Subsequence::new(
                idx.clone(),
                data.index(idx).fold(Vec::new(), |mut acc, s| {
                    acc.extend_from_slice(s);
                    acc
                }),
            )
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
        let sent_authed = sent_idx
            .iter()
            .flat_map(|range| self.sent[range].iter().copied())
            .collect();
        let received_authed = recv_idx
            .iter()
            .flat_map(|range| self.received[range].iter().copied())
            .collect();

        PartialTranscript {
            sent_authed,
            received_authed,
            sent_idx,
            recv_idx,
            sent_total: self.sent.len(),
            recv_total: self.received.len(),
        }
    }
}

/// A partial transcript.
///
/// A partial transcript is a transcript which may not have all the data
/// authenticated.
///
/// Only authenticated data is stored: the bytes, and the set of ranges they
/// occupy. The total length of each direction is also carried, but when the
/// transcript comes from a peer it is untrusted — it is only ever compared
/// against a caller-provided length, never used to size an allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "validation::PartialTranscriptUnchecked")]
#[cfg_attr(test, derive(PartialEq))]
pub struct PartialTranscript {
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

impl PartialTranscript {
    /// Returns the index of sent data which have been authenticated.
    pub fn sent_authed(&self) -> &RangeSet<usize> {
        &self.sent_idx
    }

    /// Returns the index of received data which have been authenticated.
    pub fn received_authed(&self) -> &RangeSet<usize> {
        &self.recv_idx
    }

    /// Returns the sent data which have been authenticated.
    pub(crate) fn sent_authed_bytes(&self) -> &[u8] {
        &self.sent_authed
    }

    /// Returns the received data which have been authenticated.
    pub(crate) fn received_authed_bytes(&self) -> &[u8] {
        &self.received_authed
    }

    /// Returns the total length of the sent data.
    #[allow(clippy::len_without_is_empty)]
    pub fn len_sent(&self) -> usize {
        self.sent_total
    }

    /// Returns the total length of the received data.
    #[allow(clippy::len_without_is_empty)]
    pub fn len_received(&self) -> usize {
        self.recv_total
    }

    /// Unions the authenticated data of another compressed transcript into this
    /// one.
    ///
    /// Where both transcripts authenticate the same position, `self` takes
    /// precedence.
    ///
    /// # Panics
    ///
    /// Panics if the transcripts are not the same length.
    pub fn union_transcript(&mut self, other: &PartialTranscript) {
        assert_eq!(
            self.sent_total, other.sent_total,
            "sent data are not the same length"
        );
        assert_eq!(
            self.recv_total, other.recv_total,
            "received data are not the same length"
        );

        let (sent_idx, sent_authed) = overlay(
            &self.sent_idx,
            &self.sent_authed,
            &other.sent_idx,
            &other.sent_authed,
        );
        let (recv_idx, received_authed) = overlay(
            &self.recv_idx,
            &self.received_authed,
            &other.recv_idx,
            &other.received_authed,
        );

        self.sent_idx = sent_idx;
        self.sent_authed = sent_authed;
        self.recv_idx = recv_idx;
        self.received_authed = received_authed;
    }

    /// Unions an authenticated subsequence into this transcript.
    ///
    /// Where the subsequence overlaps already authenticated data, the
    /// subsequence takes precedence.
    ///
    /// # Panics
    ///
    /// Panics if the subsequence is out of bounds of the transcript.
    pub fn union_subsequence(&mut self, direction: Direction, seq: &Subsequence) {
        let total = match direction {
            Direction::Sent => self.sent_total,
            Direction::Received => self.recv_total,
        };

        if seq.index().end().unwrap_or(0) > total {
            panic!("subsequence is out of bounds of the transcript");
        }

        match direction {
            Direction::Sent => {
                let (idx, data) =
                    overlay(seq.index(), seq.data(), &self.sent_idx, &self.sent_authed);
                self.sent_idx = idx;
                self.sent_authed = data;
            }
            Direction::Received => {
                let (idx, data) = overlay(
                    seq.index(),
                    seq.data(),
                    &self.recv_idx,
                    &self.received_authed,
                );
                self.recv_idx = idx;
                self.received_authed = data;
            }
        }
    }

    /// Returns the authenticated bytes of the given transcript position range.
    ///
    /// Returns `None` if the range is not fully authenticated, i.e. it spans a
    /// gap or more than one authenticated range.
    pub(crate) fn locate(&self, direction: Direction, range: &Range<usize>) -> Option<&[u8]> {
        let (idx, bytes) = match direction {
            Direction::Sent => (&self.sent_idx, self.sent_authed_bytes()),
            Direction::Received => (&self.recv_idx, self.received_authed_bytes()),
        };

        locate(idx, bytes, range)
    }

    /// Returns the sent data, materialized to `expected` bytes.
    ///
    /// # Warning
    ///
    /// Only the positions in [`sent_authed`](PartialTranscript::sent_authed)
    /// have been authenticated; every other position is `0`.
    ///
    /// The allocation is sized by `expected`, a length the caller trusts (for
    /// example the length recorded by the Verifier, or a signed
    /// [`TranscriptLength`](crate::connection::TranscriptLength)), never by the
    /// length carried by this transcript. Returns an error if `expected` does
    /// not match the length carried by this transcript.
    pub fn sent_unsafe(&self, expected: usize) -> Result<Vec<u8>, InvalidTranscriptLength> {
        self.expand(Direction::Sent, expected)
    }

    /// Returns the received data, materialized to `expected` bytes.
    ///
    /// # Warning
    ///
    /// Only the positions in
    /// [`received_authed`](PartialTranscript::received_authed) have been
    /// authenticated; every other position is `0`.
    ///
    /// The allocation is sized by `expected`, a length the caller trusts, never
    /// by the length carried by this transcript. Returns an error if `expected`
    /// does not match the length carried by this transcript.
    pub fn received_unsafe(&self, expected: usize) -> Result<Vec<u8>, InvalidTranscriptLength> {
        self.expand(Direction::Received, expected)
    }

    fn expand(
        &self,
        direction: Direction,
        expected: usize,
    ) -> Result<Vec<u8>, InvalidTranscriptLength> {
        let (idx, bytes, total) = match direction {
            Direction::Sent => (&self.sent_idx, self.sent_authed_bytes(), self.sent_total),
            Direction::Received => (
                &self.recv_idx,
                self.received_authed_bytes(),
                self.recv_total,
            ),
        };

        if total != expected {
            return Err(InvalidTranscriptLength {
                expected,
                actual: total,
            });
        }

        let mut out = vec![0; expected];
        let mut offset = 0;
        for range in idx.iter() {
            out[range.clone()].copy_from_slice(&bytes[offset..offset + range.len()]);
            offset += range.len();
        }

        Ok(out)
    }

    /// Materializes the bytes of `range` for a direction, filling
    /// unauthenticated positions with `0`.
    pub(crate) fn materialize_range(&self, direction: Direction, range: &Range<usize>) -> Vec<u8> {
        let (idx, bytes) = match direction {
            Direction::Sent => (&self.sent_idx, self.sent_authed_bytes()),
            Direction::Received => (&self.recv_idx, self.received_authed_bytes()),
        };

        let mut out = Vec::with_capacity(range.len());
        let mut pos = range.start;
        let mut offset = 0;

        for r in idx.iter() {
            if r.end <= pos {
                offset += r.len();
                continue;
            }
            if r.start >= range.end {
                break;
            }

            if pos < r.start {
                let end = r.start.min(range.end);
                out.resize(out.len() + (end - pos), 0);
                pos = end;
            }

            let start = pos.max(r.start);
            let end = r.end.min(range.end);
            if start < end {
                out.extend_from_slice(&bytes[offset + (start - r.start)..offset + (end - r.start)]);
                pos = end;
            }

            offset += r.len();

            if pos >= range.end {
                break;
            }
        }

        if pos < range.end {
            out.resize(out.len() + (range.end - pos), 0);
        }

        out
    }
}

/// Invalid transcript length error.
#[derive(Debug, thiserror::Error)]
#[error("invalid transcript length: expected {expected}, got {actual}")]
pub struct InvalidTranscriptLength {
    /// The expected length.
    pub expected: usize,
    /// The actual length.
    pub actual: usize,
}

/// Locates the byte slice of `range` within `bytes`, where `bytes` is the
/// concatenation of the authenticated positions of `idx` in ascending order.
///
/// Returns `None` if `range` is not fully authenticated.
fn locate<'a>(idx: &RangeSet<usize>, bytes: &'a [u8], range: &Range<usize>) -> Option<&'a [u8]> {
    let mut offset = 0;
    for r in idx.iter() {
        if range.start >= r.start && range.end <= r.end {
            let start = offset + (range.start - r.start);
            return Some(&bytes[start..start + range.len()]);
        }
        offset += r.len();
    }
    None
}

/// Overlays the authenticated data of `lose` onto `win`, with `win` taking
/// precedence where both authenticate the same position.
///
/// Both inputs are `(index, bytes)` pairs where `bytes` is the concatenation of
/// the authenticated positions of `index` in ascending order. The result is the
/// same representation for the union of the two index sets.
fn overlay(
    win_idx: &RangeSet<usize>,
    win_bytes: &[u8],
    lose_idx: &RangeSet<usize>,
    lose_bytes: &[u8],
) -> (RangeSet<usize>, Vec<u8>) {
    let delta = lose_idx.difference(win_idx).into_set();
    let lose_delta = subset_bytes(lose_idx, lose_bytes, &delta);
    merge_disjoint(win_idx, win_bytes, &delta, &lose_delta)
}

/// Returns the bytes of `idx` restricted to `subset`, concatenated in ascending
/// order.
///
/// `subset` is assumed to be a subset of `idx`.
fn subset_bytes(idx: &RangeSet<usize>, bytes: &[u8], subset: &RangeSet<usize>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut sub = subset.iter().peekable();

    for range in idx.iter() {
        while let Some(s) = sub.peek().cloned() {
            if s.end <= range.start {
                sub.next();
                continue;
            }
            if s.start >= range.end {
                break;
            }

            let start = s.start.max(range.start);
            let end = s.end.min(range.end);
            out.extend_from_slice(
                &bytes[offset + (start - range.start)..offset + (end - range.start)],
            );

            if s.end <= range.end {
                sub.next();
            } else {
                break;
            }
        }

        offset += range.len();
    }

    out
}

/// Merges two concatenated byte runs whose index sets are disjoint.
fn merge_disjoint(
    a_idx: &RangeSet<usize>,
    a_bytes: &[u8],
    b_idx: &RangeSet<usize>,
    b_bytes: &[u8],
) -> (RangeSet<usize>, Vec<u8>) {
    let mut ranges = Vec::new();
    let mut bytes = Vec::with_capacity(a_bytes.len() + b_bytes.len());

    let mut a = a_idx.iter().peekable();
    let mut b = b_idx.iter().peekable();
    let mut ao = 0;
    let mut bo = 0;

    loop {
        let take_a = match (a.peek(), b.peek()) {
            (Some(a), Some(b)) => a.start < b.start,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };

        if take_a {
            let range = a.next().unwrap();
            bytes.extend_from_slice(&a_bytes[ao..ao + range.len()]);
            ao += range.len();
            ranges.push(range);
        } else {
            let range = b.next().unwrap();
            bytes.extend_from_slice(&b_bytes[bo..bo + range.len()]);
            bo += range.len();
            ranges.push(range);
        }
    }

    (RangeSet::new_from_slice(&ranges), bytes)
}

impl PartialTranscript {
    /// Creates a new partial transcript initialized to all 0s.
    ///
    /// # Arguments
    ///
    /// * `sent_len` - The length of the sent data.
    /// * `received_len` - The length of the received data.
    pub fn new(sent_len: usize, received_len: usize) -> Self {
        Self {
            sent_authed: Vec::new(),
            received_authed: Vec::new(),
            sent_idx: RangeSet::default(),
            recv_idx: RangeSet::default(),
            sent_total: sent_len,
            recv_total: received_len,
        }
    }

    /// Returns whether the transcript is complete.
    pub fn is_complete(&self) -> bool {
        self.sent_idx.len() == self.sent_total && self.recv_idx.len() == self.recv_total
    }

    /// Returns whether the index is in bounds of the transcript.
    pub fn contains(&self, direction: Direction, idx: &RangeSet<usize>) -> bool {
        match direction {
            Direction::Sent => idx.end().unwrap_or(0) <= self.sent_total,
            Direction::Received => idx.end().unwrap_or(0) <= self.recv_total,
        }
    }

    /// Returns the index of sent data which haven't been authenticated.
    pub fn sent_unauthed(&self) -> RangeSet<usize> {
        (0..self.sent_total).difference(&self.sent_idx).into_set()
    }

    /// Returns the index of received data which haven't been authenticated.
    pub fn received_unauthed(&self) -> RangeSet<usize> {
        (0..self.recv_total).difference(&self.recv_idx).into_set()
    }

    /// Returns an iterator over the authenticated data in the transcript.
    pub fn iter(&self, direction: Direction) -> impl Iterator<Item = u8> + '_ {
        let bytes = match direction {
            Direction::Sent => &self.sent_authed,
            Direction::Received => &self.received_authed,
        };

        bytes.iter().copied()
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
    #[cfg(test)]
    pub(crate) fn copy_to(&self, dest: &mut [u8]) {
        let mut offset = 0;
        for range in self.idx.iter() {
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

    /// Invalid partial transcript error.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid partial transcript: {0}")]
    pub struct InvalidPartialTranscript(&'static str);

    #[derive(Debug, Deserialize)]
    #[cfg_attr(test, derive(Serialize))]
    pub(super) struct PartialTranscriptUnchecked {
        sent_authed: Vec<u8>,
        received_authed: Vec<u8>,
        sent_idx: RangeSet<usize>,
        recv_idx: RangeSet<usize>,
        sent_total: usize,
        recv_total: usize,
    }

    impl TryFrom<PartialTranscriptUnchecked> for PartialTranscript {
        type Error = InvalidPartialTranscript;

        fn try_from(unchecked: PartialTranscriptUnchecked) -> Result<Self, Self::Error> {
            if unchecked.sent_authed.len() != unchecked.sent_idx.len()
                || unchecked.received_authed.len() != unchecked.recv_idx.len()
            {
                return Err(InvalidPartialTranscript(
                    "lengths of index and data don't match",
                ));
            }

            if unchecked.sent_idx.end().unwrap_or(0) > unchecked.sent_total
                || unchecked.recv_idx.end().unwrap_or(0) > unchecked.recv_total
            {
                return Err(InvalidPartialTranscript(
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
        fn partial_transcript() -> PartialTranscriptUnchecked {
            PartialTranscriptUnchecked {
                received_authed: vec![1, 2, 3, 11, 12, 13],
                sent_authed: vec![4, 5, 6, 14, 15, 16],
                recv_idx: RangeSet::from([1..4, 11..14]),
                sent_idx: RangeSet::from([4..7, 14..17]),
                sent_total: 20,
                recv_total: 20,
            }
        }

        #[rstest]
        fn test_partial_transcript_valid(partial_transcript: PartialTranscriptUnchecked) {
            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<PartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_ok());
        }

        #[rstest]
        // Expect to fail since the length of data and the length of the index
        // do not match.
        fn test_partial_transcript_invalid_lengths(
            mut partial_transcript: PartialTranscriptUnchecked,
        ) {
            // Add an extra byte to the data.
            let mut old = partial_transcript.sent_authed;
            old.extend([1]);
            partial_transcript.sent_authed = old;

            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<PartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_err());
        }

        #[rstest]
        // Expect to fail since the index is out of bounds.
        fn test_partial_transcript_invalid_ranges(
            mut partial_transcript: PartialTranscriptUnchecked,
        ) {
            // Change the total to be less than the last range's end bound.
            let end = partial_transcript.sent_idx.iter().next_back().unwrap().end;

            partial_transcript.sent_total = end - 1;

            let bytes = bincode::serialize(&partial_transcript).unwrap();
            let transcript: Result<PartialTranscript, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(transcript.is_err());
        }

        #[rstest]
        // A peer can declare an arbitrarily large total. Parsing must not
        // allocate from it (this used to abort via `vec![0; total]`), and
        // materializing against a trusted length must refuse rather than size
        // the allocation by the declared total.
        fn test_partial_transcript_huge_total_does_not_allocate() {
            let unchecked = PartialTranscriptUnchecked {
                received_authed: Vec::new(),
                sent_authed: Vec::new(),
                recv_idx: RangeSet::default(),
                sent_idx: RangeSet::default(),
                sent_total: 1 << 62,
                recv_total: 0,
            };
            let bytes = bincode::serialize(&unchecked).unwrap();

            let transcript: PartialTranscript = bincode::deserialize(&bytes).unwrap();
            assert_eq!(transcript.len_sent(), 1 << 62);

            // A mismatched expected length is refused; no allocation happens.
            assert!(transcript.sent_unsafe(12).is_err());
        }

        #[rstest]
        // Deserializing a transcript embedded in a proof must not abort on an
        // oversized declared total either.
        fn test_transcript_proof_huge_total_does_not_allocate() {
            let unchecked = PartialTranscriptUnchecked {
                received_authed: Vec::new(),
                sent_authed: Vec::new(),
                recv_idx: RangeSet::default(),
                sent_idx: RangeSet::default(),
                sent_total: 1 << 62,
                recv_total: 0,
            };
            let bytes = bincode::serialize(&unchecked).unwrap();

            // The trailing `hash_secrets` field is missing, so this errors; the
            // point is that it returns rather than aborting.
            let proof: Result<TranscriptProof, Box<bincode::ErrorKind>> =
                bincode::deserialize(&bytes);
            assert!(proof.is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    fn sent_bytes(partial: &PartialTranscript) -> Vec<u8> {
        partial.sent_unsafe(partial.len_sent()).unwrap()
    }

    fn recv_bytes(partial: &PartialTranscript) -> Vec<u8> {
        partial.received_unsafe(partial.len_received()).unwrap()
    }

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
        assert_eq!(sent_bytes(&partial), [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(recv_bytes(&partial), [0, 0, 0, 3, 4, 5, 6, 0, 0, 0, 0, 0]);
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
            sent_bytes(&simple_partial),
            [0, 1, 0, 3, 4, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            recv_bytes(&simple_partial),
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
            sent_bytes(&simple_partial),
            [0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            recv_bytes(&simple_partial),
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
            sent_bytes(&overlap_partial),
            [0, 0, 0, 3, 4, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            recv_bytes(&overlap_partial),
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
            sent_bytes(&equal_partial),
            [0, 0, 0, 0, 4, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            recv_bytes(&equal_partial),
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
            sent_bytes(&subset_partial),
            [0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 0, 0]
        );
        assert_eq!(
            recv_bytes(&subset_partial),
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

        assert_eq!(sent_bytes(&partial), [0, 1, 2, 0, 4, 5, 6, 7, 8, 9, 0, 0]);
        assert_eq!(recv_bytes(&partial), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0]);
        assert_eq!(partial.sent_authed(), &RangeSet::from([0..3, 4..10]));
        assert_eq!(partial.received_authed(), &RangeSet::from(0..11));

        // Overwrite with another subseq.
        let other_sent_seq = Subsequence::new(RangeSet::from(0..3), [3, 2, 1].into()).unwrap();

        partial.union_subsequence(Direction::Sent, &other_sent_seq);
        assert_eq!(sent_bytes(&partial), [3, 2, 1, 0, 4, 5, 6, 7, 8, 9, 0, 0]);
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

    #[rstest]
    fn test_compressed_union(transcript: Transcript) {
        // self authenticates [4..10], other authenticates [0..3, 5..9].
        let mut a = transcript.to_partial(RangeSet::from(4..10), RangeSet::default());
        let b = transcript.to_partial(RangeSet::from([0..3, 5..9]), RangeSet::default());

        a.union_transcript(&b);

        // self wins on the overlap [5..9]; other only contributes [0..3].
        assert_eq!(a.sent_authed(), &RangeSet::from([0..3, 4..10]));
        assert_eq!(a.sent_authed_bytes(), &[0, 1, 2, 4, 5, 6, 7, 8, 9]);
    }

    #[rstest]
    fn test_compressed_union_precedence() {
        // self authenticates [0..2] with [9, 9]; other authenticates [1..4]
        // with positions [1, 2, 3] = [1, 1, 1].
        let mut a = PartialTranscript {
            sent_authed: vec![9, 9],
            received_authed: Vec::new(),
            sent_idx: RangeSet::from(0..2),
            recv_idx: RangeSet::default(),
            sent_total: 4,
            recv_total: 0,
        };
        let b = PartialTranscript {
            sent_authed: vec![1, 1, 1],
            received_authed: Vec::new(),
            sent_idx: RangeSet::from(1..4),
            recv_idx: RangeSet::default(),
            sent_total: 4,
            recv_total: 0,
        };

        a.union_transcript(&b);

        // self keeps [0..2]; other contributes only [2..4].
        assert_eq!(a.sent_authed(), &RangeSet::from(0..4));
        assert_eq!(a.sent_authed_bytes(), &[9, 9, 1, 1]);
    }

    #[rstest]
    fn test_compressed_union_subsequence(transcript: Transcript) {
        let mut compressed = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));

        let sent_seq =
            Subsequence::new(RangeSet::from([0..3, 5..7]), [0, 1, 2, 5, 6].into()).unwrap();
        let recv_seq =
            Subsequence::new(RangeSet::from([0..4, 5..7]), [0, 1, 2, 3, 5, 6].into()).unwrap();

        compressed.union_subsequence(Direction::Sent, &sent_seq);
        compressed.union_subsequence(Direction::Received, &recv_seq);

        assert_eq!(compressed.sent_authed(), &RangeSet::from([0..3, 4..10]));
        assert_eq!(compressed.sent_authed_bytes(), &[0, 1, 2, 4, 5, 6, 7, 8, 9]);
        assert_eq!(compressed.received_authed(), &RangeSet::from(0..11));
        assert_eq!(
            compressed.received_authed_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );

        // Overwrite with another subseq.
        let other_sent_seq = Subsequence::new(RangeSet::from(0..3), [3, 2, 1].into()).unwrap();
        compressed.union_subsequence(Direction::Sent, &other_sent_seq);

        assert_eq!(compressed.sent_authed(), &RangeSet::from([0..3, 4..10]));
        assert_eq!(compressed.sent_authed_bytes(), &[3, 2, 1, 4, 5, 6, 7, 8, 9]);
    }

    #[rstest]
    #[should_panic]
    fn test_compressed_union_subsequence_out_of_bounds(transcript: Transcript) {
        let mut compressed = transcript.to_partial(RangeSet::from(4..10), RangeSet::from(3..11));

        let sent_seq =
            Subsequence::new(RangeSet::from([0..3, 13..15]), [0, 1, 2, 5, 6].into()).unwrap();

        compressed.union_subsequence(Direction::Sent, &sent_seq);
    }

    #[rstest]
    fn test_compressed_locate(transcript: Transcript) {
        let compressed = transcript.to_partial(RangeSet::from([1..4, 6..9]), RangeSet::default());

        // Fully authenticated.
        assert_eq!(
            compressed.locate(Direction::Sent, &(2..4)),
            Some([2u8, 3].as_slice())
        );
        // Spans the gap between [1..4] and [6..9].
        assert_eq!(compressed.locate(Direction::Sent, &(3..7)), None);
        // Partially authenticated.
        assert_eq!(compressed.locate(Direction::Sent, &(0..2)), None);
        // Not authenticated at all.
        assert_eq!(compressed.locate(Direction::Sent, &(9..12)), None);
    }

    #[rstest]
    fn test_compressed_sent_unsafe(transcript: Transcript) {
        let compressed = transcript.to_partial(RangeSet::from(4..8), RangeSet::from(3..5));

        let sent = compressed.sent_unsafe(12).unwrap();
        assert_eq!(sent, [0, 0, 0, 0, 4, 5, 6, 7, 0, 0, 0, 0]);
        assert_eq!(sent.len(), 12);

        let received = compressed.received_unsafe(12).unwrap();
        assert_eq!(received, [0, 0, 0, 3, 4, 0, 0, 0, 0, 0, 0, 0]);

        // A mismatched length is refused rather than sized by the transcript.
        assert!(compressed.sent_unsafe(11).is_err());
        assert!(compressed.sent_unsafe(1 << 62).is_err());
    }

    #[rstest]
    fn test_materialize_range_fills_gaps(transcript: Transcript) {
        let compressed = transcript.to_partial(RangeSet::from([1..3, 6..8]), RangeSet::default());

        // Authenticated positions keep their bytes; gaps are zero.
        assert_eq!(
            compressed.materialize_range(Direction::Sent, &(0..9)),
            [0, 1, 2, 0, 0, 0, 6, 7, 0]
        );
        // A range fully inside a gap is all zeros.
        assert_eq!(
            compressed.materialize_range(Direction::Sent, &(3..6)),
            [0, 0, 0]
        );
    }
}
