//! Substring proofs based on garbling labels.

use super::{SubstringProofBuilder, SubstringProofBuilderError};
use crate::{msg::DecodingInfo, Direction, RedactedTranscript, TranscriptSlice};
use mpz_circuits::types::Value;
use mpz_garble::value::ValueRef;
use thiserror::Error;
use utils::range::{RangeSet, RangeUnion};

/// A proof builder which generates substring proofs for garbling labels
#[derive(Debug)]
pub struct LabelProofBuilder {
    sent_len: usize,
    sent_label: String,
    sent_reveal: RangeSet<usize>,

    recv_len: usize,
    recv_label: String,
    recv_reveal: RangeSet<usize>,
}

impl LabelProofBuilder {
    /// Create a new proof builder
    ///
    /// # Arguments
    /// * `sent_len` - The length of the sent transcript
    /// * `sent_label` - The label for the sent transcript
    /// * `recv_len` - The length of the received transcript
    /// * `recv_label` - The label for the received transcript
    pub fn new(
        sent_len: usize,
        sent_label: impl Into<String>,
        recv_len: usize,
        recv_label: impl Into<String>,
    ) -> Self {
        Self {
            sent_len,
            sent_label: sent_label.into(),
            sent_reveal: RangeSet::default(),

            recv_len,
            recv_label: recv_label.into(),
            recv_reveal: RangeSet::default(),
        }
    }

    /// Collects the transcript parts which are to be revealed
    ///
    /// # Arguments
    /// * `ranges` - The ranges to reveal
    /// * `direction` - The direction of the transcript
    pub fn reveal_ranges(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut LabelProofBuilder, LabelProofBuilderError> {
        if ranges.is_empty() {
            return Err(LabelProofBuilderError::EmptyRange);
        }

        match direction {
            Direction::Sent
                if ranges.max().expect("Range should be non-empty") <= self.sent_len =>
            {
                self.sent_reveal = self.sent_reveal.union(&ranges)
            }
            Direction::Received
                if ranges.max().expect("Range should be non-empty") <= self.recv_len =>
            {
                self.recv_reveal = self.recv_reveal.union(&ranges)
            }
            _ => return Err(LabelProofBuilderError::RangeTooBig),
        }
        Ok(self)
    }

    /// Build the [LabelProof] which contains the ranges which will be revealed
    pub fn build_proof(self) -> Result<LabelProof, LabelProofBuilderError> {
        Ok(LabelProof {
            sent_len: self.sent_len,
            sent_label: self.sent_label,
            sent_ids: self.sent_reveal,
            sent_decoded_values: vec![],

            recv_len: self.recv_len,
            recv_label: self.recv_label,
            recv_ids: self.recv_reveal,
            recv_decoded_values: vec![],
        })
    }
}

impl SubstringProofBuilder<LabelProof> for LabelProofBuilder {
    fn reveal(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut dyn SubstringProofBuilder<LabelProof>, SubstringProofBuilderError> {
        Ok(self.reveal_ranges(ranges, direction)? as &mut dyn SubstringProofBuilder<_>)
    }

    fn build(self: Box<Self>) -> Result<LabelProof, SubstringProofBuilderError> {
        (*self)
            .build_proof()
            .map_err(SubstringProofBuilderError::from)
    }
}

/// An error type for [LabelProofBuilder].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum LabelProofBuilderError {
    #[error("Empty range cannot be revealed")]
    EmptyRange,
    #[error("The specified range cannot be revealed because it exceeds the transcript length")]
    RangeTooBig,
}

/// A substring proof which works with garbling labels
///
/// This proof needs to be sent to the verifier, who will use it to reveal the plaintext bytes of
/// the transcript.
pub struct LabelProof {
    pub(crate) sent_len: usize,
    pub(crate) sent_label: String,
    pub(crate) sent_ids: RangeSet<usize>,
    sent_decoded_values: Vec<Value>,

    pub(crate) recv_len: usize,
    pub(crate) recv_label: String,
    pub(crate) recv_ids: RangeSet<usize>,
    recv_decoded_values: Vec<Value>,
}

impl LabelProof {
    /// Returns the [ValueRef]s for the ids
    ///
    /// # Arguments
    /// * `provider` - A function which returns the [ValueRef] for a given id
    pub fn value_refs<'a, T: Fn(String) -> Option<ValueRef> + 'a>(
        &'a self,
        provider: T,
    ) -> impl Iterator<Item = Option<ValueRef>> + 'a {
        self.iter().map(provider)
    }

    /// Set the decoding values for the transcript
    pub fn set_decoding(&mut self, mut decoding_values: Vec<Value>) {
        let recv_values = decoding_values.split_off(self.sent_ids.len());

        self.sent_decoded_values = decoding_values;
        self.recv_decoded_values = recv_values;
    }

    /// Reconstructs the transcript from the given values
    ///
    /// Returns the sent (first) and received transcript (second)
    ///
    /// # Arguments
    /// * `sent_len` - The real length of the sent transcript
    /// * `recv_len` - The real length of the received transcript
    pub fn verify(
        &self,
        sent_len: usize,
        recv_len: usize,
    ) -> Result<(RedactedTranscript, RedactedTranscript), LabelProofError> {
        // Verify the transcript lengths
        if sent_len != self.sent_len {
            return Err(LabelProofError::TranscriptLengthMismatch {
                expected: sent_len,
                actual: self.sent_len,
            });
        }
        if recv_len != self.recv_len {
            return Err(LabelProofError::TranscriptLengthMismatch {
                expected: recv_len,
                actual: self.recv_len,
            });
        }

        // Verify the decoded values lengths
        if self.sent_decoded_values.len() != self.sent_ids.len() {
            return Err(LabelProofError::DecodedValuesLength {
                expected: self.sent_ids.len(),
                actual: self.sent_decoded_values.len(),
            });
        }
        if self.recv_decoded_values.len() != self.recv_ids.len() {
            return Err(LabelProofError::DecodedValuesLength {
                expected: self.recv_ids.len(),
                actual: self.recv_decoded_values.len(),
            });
        }

        let sent_redacted = RedactedTranscript::new(
            self.sent_len,
            ids_to_transcript_slice(&self.sent_ids, self.sent_decoded_values.as_slice()),
        );
        let recv_redacted = RedactedTranscript::new(
            self.recv_len,
            ids_to_transcript_slice(&self.recv_ids, self.recv_decoded_values.as_slice()),
        );

        Ok((sent_redacted, recv_redacted))
    }

    /// Returns an iterator over the ids
    pub fn iter(&self) -> impl Iterator<Item = String> + '_ {
        let sent_labeled = self
            .sent_ids
            .iter()
            .map(|s| format!("{}/{}", self.sent_label, s));

        let recv_labeled = self
            .recv_ids
            .iter()
            .map(|s| format!("{}/{}", self.recv_label, s));

        sent_labeled.chain(recv_labeled)
    }
}

/// Converts the ids and decoded values to a vector of [TranscriptSlice]s
fn ids_to_transcript_slice(
    ids: &RangeSet<usize>,
    decoded_values: &[Value],
) -> Vec<TranscriptSlice> {
    let mut consumed = 0;
    let mut transcript_slices = vec![];

    for range in ids.iter_ranges() {
        let transcript_slice = TranscriptSlice::new(
            range.clone(),
            decoded_values[consumed..range.len()]
                .iter()
                .map(|v| match *v {
                    Value::U8(byte) => byte,
                    _ => panic!("Only u8 values are supported"),
                })
                .collect::<Vec<u8>>(),
        );

        transcript_slices.push(transcript_slice);
        consumed += range.len();
    }

    transcript_slices
}

impl From<DecodingInfo> for LabelProof {
    fn from(value: DecodingInfo) -> Self {
        Self {
            sent_len: value.sent_len,
            sent_label: value.sent_label,
            sent_ids: value.sent_ids,
            sent_decoded_values: vec![],

            recv_len: value.recv_len,
            recv_label: value.recv_label,
            recv_ids: value.recv_ids,
            recv_decoded_values: vec![],
        }
    }
}

/// An error type for [LabelProof].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum LabelProofError {
    #[error("The proof is invalid")]
    InvalidProof,
    #[error("Transcript length mismatch, expected {expected} but got {actual}")]
    TranscriptLengthMismatch { expected: usize, actual: usize },
    #[error("Decoded values have wrong length, expected {expected} but got {actual}")]
    DecodedValuesLength { expected: usize, actual: usize },
}
