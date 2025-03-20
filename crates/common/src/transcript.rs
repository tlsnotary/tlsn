//! TLS transcript.

use mpz_memory_core::{binary::U8, Vector};
use tls_core::msgs::enums::ContentType;
use tlsn_core::transcript::{Direction, Idx, Transcript};
use rangeset::Intersection;

/// A transcript of sent and received TLS records.
#[derive(Debug, Default, Clone)]
pub struct TlsTranscript {
    /// Records sent by the prover.
    pub sent: Vec<Record>,
    /// Records received by the prover.
    pub recv: Vec<Record>,
}

impl TlsTranscript {
    /// Returns the application data transcript.
    pub fn to_transcript(&self) -> Result<Transcript, IncompleteTranscript> {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        for record in self
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(IncompleteTranscript {})?
                .clone();
            sent.extend_from_slice(&plaintext);
        }

        for record in self
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(IncompleteTranscript {})?
                .clone();
            recv.extend_from_slice(&plaintext);
        }

        Ok(Transcript::new(sent, recv))
    }

    /// Returns the application data transcript references.
    pub fn to_transcript_refs(&self) -> Result<TranscriptRefs, IncompleteTranscript> {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        for record in self
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext_ref = record
                .plaintext_ref
                .as_ref()
                .ok_or(IncompleteTranscript {})?;
            sent.push(*plaintext_ref);
        }

        for record in self
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext_ref = record
                .plaintext_ref
                .as_ref()
                .ok_or(IncompleteTranscript {})?;
            recv.push(*plaintext_ref);
        }

        Ok(TranscriptRefs { sent, recv })
    }
}

/// A TLS record.
#[derive(Clone)]
pub struct Record {
    /// Sequence number.
    pub seq: u64,
    /// Content type.
    pub typ: ContentType,
    /// Plaintext.
    pub plaintext: Option<Vec<u8>>,
    /// VM reference to the plaintext.
    pub plaintext_ref: Option<Vector<U8>>,
    /// Explicit nonce.
    pub explicit_nonce: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
}

opaque_debug::implement!(Record);

/// References to the application plaintext in the transcript.
#[derive(Debug, Default, Clone)]
pub struct TranscriptRefs {
    sent: Vec<Vector<U8>>,
    recv: Vec<Vector<U8>>,
}

impl TranscriptRefs {
    /// Returns the sent plaintext references.
    pub fn sent(&self) -> &[Vector<U8>] {
        &self.sent
    }

    /// Returns the received plaintext references.
    pub fn recv(&self) -> &[Vector<U8>] {
        &self.recv
    }

    /// Returns VM references for the given direction and index, otherwise
    /// `None` if the index is out of bounds.
    pub fn get(&self, direction: Direction, idx: &Idx) -> Option<Vec<Vector<U8>>> {
        if idx.is_empty() {
            return Some(Vec::new());
        }

        let refs = match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        };

        // Computes the transcript range for each reference.
        let mut start = 0;
        let mut slice_iter = refs.iter().map(move |slice| {
            let out = (slice, start..start + slice.len());
            start += slice.len();
            out
        });

        let mut slices = Vec::new();
        let (mut slice, mut slice_range) = slice_iter.next()?;
        for range in idx.iter_ranges() {
            loop {
                if let Some(intersection) = slice_range.intersection(&range) {
                    let start = intersection.start - slice_range.start;
                    let end = intersection.end - slice_range.start;
                    slices.push(slice.get(start..end).expect("range should be in bounds"));
                }

                // Proceed to next range if the current slice extends beyond. Otherwise, proceed
                // to the next slice.
                if range.end <= slice_range.end {
                    break;
                } else {
                    (slice, slice_range) = slice_iter.next()?;
                }
            }
        }

        Some(slices)
    }
}

/// Error for [`TranscriptRefs::from_transcript`].
#[derive(Debug, thiserror::Error)]
#[error("not all application plaintext was committed to in the TLS transcript")]
pub struct IncompleteTranscript {}
