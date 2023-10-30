//! Substring proofs based on garbling labels.

use super::{SubstringProofBuilder, SubstringProofBuilderError};
use crate::{msg::DecodingInfo, Direction, RedactedTranscript};
use mpz_circuits::types::Value;
use mpz_garble::value::ValueRef;
use thiserror::Error;
use utils::range::{RangeSet, RangeUnion};

/// A proof builder which generates substring proofs for garbling labels
#[derive(Debug)]
pub struct LabelProofBuilder {
    sent_len: usize,
    reveal_sent: RangeSet<usize>,
    recv_len: usize,
    reveal_recv: RangeSet<usize>,
}

impl LabelProofBuilder {
    /// Create a new proof builder
    ///
    /// # Arguments
    /// * `sent_len` - The length of the sent transcript
    /// * `recv_len` - The length of the received transcript
    pub fn new(sent_len: usize, recv_len: usize) -> Self {
        Self {
            sent_len,
            reveal_sent: RangeSet::default(),
            recv_len,
            reveal_recv: RangeSet::default(),
        }
    }

    /// Collects the transcript parts which are to be revealed
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
                self.reveal_sent = self.reveal_sent.union(&ranges)
            }
            Direction::Received
                if ranges.max().expect("Range should be non-empty") <= self.recv_len =>
            {
                self.reveal_recv = self.reveal_recv.union(&ranges)
            }
            _ => return Err(LabelProofBuilderError::RangeTooBig),
        }
        Ok(self)
    }

    /// Build the [LabelProof] which contains the ranges which will be revealed
    pub fn build_proof(self) -> Result<LabelProof, LabelProofBuilderError> {
        let sent_ids = self
            .reveal_sent
            .iter()
            .map(|range| format!("tx/{}", range))
            .collect();
        let recv_ids = self
            .reveal_recv
            .iter()
            .map(|range| format!("rx/{}", range))
            .collect();
        Ok(LabelProof {
            sent_ids,
            sent_len: self.sent_len,
            sent_decoding_values: vec![],

            recv_ids,
            recv_len: self.recv_len,
            recv_decoding_values: vec![],
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
    pub(crate) sent_ids: Vec<String>,
    pub(crate) sent_len: usize,
    sent_decoding_values: Vec<Value>,

    pub(crate) recv_ids: Vec<String>,
    pub(crate) recv_len: usize,
    recv_decoding_values: Vec<Value>,
}

impl LabelProof {
    /// Returns the ids of the sent transcript parts which are to be revealed
    pub fn sent_ids(&self) -> &[String] {
        &self.sent_ids
    }

    /// Returns the ids of the received transcript parts which are to be revealed
    pub fn recv_ids(&self) -> &[String] {
        &self.recv_ids
    }

    /// Returns the [ValueRef]s for the ids
    pub fn value_refs<'a, T: Fn(&'a str) -> Option<ValueRef> + 'a>(
        &'a self,
        provider: T,
    ) -> impl Iterator<Item = Option<ValueRef>> + 'a {
        self.iter().map(provider)
    }

    /// Set the decoding values for the transcript
    pub fn set_decoding(&mut self, mut decoding_values: Vec<Value>) {
        let recv_values = decoding_values.split_off(self.sent_ids.len());

        self.sent_decoding_values = decoding_values;
        self.recv_decoding_values = recv_values;
    }

    /// Reconstructs the transcript from the given values
    ///
    /// Returns the sent (first) and received transcript (second)
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

        todo!()
    }

    /// Returns an iterator over the ids
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.sent_ids
            .iter()
            .chain(self.recv_ids.iter())
            .map(|s| s.as_str())
    }
}

impl From<DecodingInfo> for LabelProof {
    fn from(value: DecodingInfo) -> Self {
        Self {
            sent_len: value.sent_len,
            sent_ids: value.sent_ids,
            sent_decoding_values: vec![],

            recv_len: value.recv_len,
            recv_ids: value.recv_ids,
            recv_decoding_values: vec![],
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
}
