//! Substring proofs based on garbling labels.

use super::{SubstringProofBuilder, SubstringProofBuilderError};
use crate::Direction;
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
        Ok(LabelProof { sent_ids, recv_ids })
    }
}

impl SubstringProofBuilder<LabelProof> for LabelProofBuilder {
    fn reveal(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut dyn SubstringProofBuilder<LabelProof>, SubstringProofBuilderError> {
        let out = self.reveal_ranges(ranges, direction)? as &mut dyn SubstringProofBuilder<_>;
        Ok(out)
    }

    fn build(self: Box<Self>) -> Result<LabelProof, SubstringProofBuilderError> {
        (*self)
            .build_proof()
            .map_err(SubstringProofBuilderError::from)
    }
}

/// An error which can occur while building a [LabelProof].
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
    sent_ids: Vec<String>,
    recv_ids: Vec<String>,
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
    pub fn value_refs<'a>(
        &'a self,
        provider: &'a dyn Fn(&str) -> Option<ValueRef>,
    ) -> impl Iterator<Item = Option<ValueRef>> + 'a {
        self.sent_ids
            .iter()
            .chain(self.recv_ids.iter())
            .map(|id| provider(id))
    }
}
