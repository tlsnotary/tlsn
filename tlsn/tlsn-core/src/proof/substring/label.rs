//! Substring proofs based on garbling labels.

use super::{SubstringProofBuilder, SubstringProofBuilderError};
use crate::{msg::DecodingInfo, Direction, RedactedTranscript, TranscriptSlice};
use mpz_circuits::types::Value;
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
    /// Creates a new proof
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
            sent_ids: RangeSet::default(),
            sent_decoded_values: vec![],

            recv_len,
            recv_label: recv_label.into(),
            recv_ids: RangeSet::default(),
            recv_decoded_values: vec![],
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
    ) -> Result<(), LabelProofError> {
        if ranges.is_empty() {
            return Err(LabelProofError::EmptyRange);
        }

        match direction {
            Direction::Sent
                if ranges.max().expect("Range should be non-empty") <= self.sent_len =>
            {
                self.sent_ids = self.sent_ids.union(&ranges)
            }
            Direction::Received
                if ranges.max().expect("Range should be non-empty") <= self.recv_len =>
            {
                self.recv_ids = self.recv_ids.union(&ranges)
            }
            _ => return Err(LabelProofError::RangeTooBig),
        }

        Ok(())
    }

    /// Set the decoding values for the transcript
    pub fn set_decoding(&mut self, mut decoding_values: Vec<Value>) -> Result<(), LabelProofError> {
        let recv_values = decoding_values.split_off(self.sent_ids.len());

        // Verify the decoded values lengths
        if decoding_values.len() != self.sent_ids.len() {
            return Err(LabelProofError::DecodedValuesLength {
                expected: self.sent_ids.len(),
                actual: decoding_values.len(),
            });
        }
        if recv_values.len() != self.recv_ids.len() {
            return Err(LabelProofError::DecodedValuesLength {
                expected: self.recv_ids.len(),
                actual: recv_values.len(),
            });
        }

        self.sent_decoded_values = decoding_values;
        self.recv_decoded_values = recv_values;

        Ok(())
    }

    /// Reconstructs the transcript from the given values
    ///
    /// Returns the sent (first) and received transcript (second)
    pub fn reconstruct(&self) -> Result<(RedactedTranscript, RedactedTranscript), LabelProofError> {
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
    pub fn iter_ids(&self) -> impl Iterator<Item = String> + '_ {
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

    /// Creates a new [LabelProof] from the given [DecodingInfo]
    ///
    /// Also needs the lengths of the sent and received transcripts.
    pub fn from_decoding_info(decoding: DecodingInfo, sent_len: usize, recv_len: usize) -> Self {
        let DecodingInfo {
            sent_label,
            sent_ids,
            recv_label,
            recv_ids,
        } = decoding;

        Self {
            sent_len,
            sent_label,
            sent_ids,
            sent_decoded_values: vec![],

            recv_len,
            recv_label,
            recv_ids,
            recv_decoded_values: vec![],
        }
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

/// An error type for [LabelProof].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum LabelProofError {
    #[error("Decoded values have wrong length, expected {expected} but got {actual}")]
    DecodedValuesLength { expected: usize, actual: usize },
    #[error("Empty range cannot be revealed")]
    EmptyRange,
    #[error("The specified range cannot be revealed because it exceeds the transcript length")]
    RangeTooBig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_label_proof() {
        let proof = build_test_label_proof();

        assert_eq!(proof.sent_len, 10);
        assert_eq!(proof.recv_len, 12);

        assert_eq!(proof.sent_label, "tx");
        assert_eq!(proof.recv_label, "rx");

        assert_eq!(
            proof.sent_ids,
            RangeSet::from(2..5_usize).union(&(5..8)).union(&(8..9))
        );
        assert_eq!(proof.recv_ids, RangeSet::from(0..3));
    }

    #[test]
    fn test_label_proof_iter_ids() {
        let proof = build_test_label_proof();
        let value_refs = proof.iter_ids().collect::<Vec<String>>();

        let range_set_sent = RangeSet::from(2..5_usize).union(&(5..8)).union(&(8..9));
        let range_set_recv = RangeSet::from(0..3_usize);

        let expected_value_refs = range_set_sent
            .iter()
            .map(|s| format!("tx/{}", s))
            .chain(range_set_recv.iter().map(|s| format!("rx/{}", s)))
            .collect::<Vec<String>>();

        assert_eq!(value_refs, expected_value_refs);
    }

    #[test]
    fn test_label_proof_set_decoding() {
        let mut proof = build_test_label_proof();
        let decoding_values = build_test_decoding_values();
        proof.set_decoding(decoding_values.clone()).unwrap();

        assert_eq!(proof.sent_decoded_values, decoding_values[..7]);
        assert_eq!(proof.recv_decoded_values, decoding_values[7..]);
    }

    #[test]
    fn test_label_proof_verify() {
        let mut proof = build_test_label_proof();
        let decoding_values = build_test_decoding_values();
        proof.set_decoding(decoding_values.clone()).unwrap();

        let (sent, received) = proof.reconstruct().unwrap();

        assert_eq!(sent.data(), &[0, 0, 1, 2, 3, 4, 5, 6, 7, 0]);
        assert_eq!(received.data(), &[8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(sent.authed(), &RangeSet::from(2..9));
        assert_eq!(received.authed(), &RangeSet::from(0..3));

        assert_eq!(sent.redacted(), &RangeSet::from(0..2).union(&(9..10)));
        assert_eq!(received.redacted(), &RangeSet::from(3..12));
    }

    fn build_test_label_proof() -> LabelProof {
        let mut builder = LabelProofBuilder::new(10, "tx", 12, "rx");
        builder
            .reveal_ranges((2..5).into(), Direction::Sent)
            .unwrap()
            .reveal_ranges(RangeSet::from(5..8).union(&(8..9)), Direction::Sent)
            .unwrap()
            .reveal_ranges((0..3).into(), Direction::Received)
            .unwrap();
        builder.build_proof().unwrap()
    }

    fn build_test_decoding_values() -> Vec<Value> {
        vec![
            // Sent
            Value::U8(1),
            Value::U8(2),
            Value::U8(3),
            Value::U8(4),
            Value::U8(5),
            Value::U8(6),
            Value::U8(7),
            // Received
            Value::U8(8),
            Value::U8(9),
            Value::U8(10),
        ]
    }
}
