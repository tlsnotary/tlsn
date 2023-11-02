//! Substring proofs based on garbling labels.

use crate::{msg::DecodingInfo, Direction, RedactedTranscript, TranscriptSlice};
use mpz_circuits::types::Value;
use thiserror::Error;
use utils::range::{RangeSet, RangeUnion};

/// A substring proof which works without commitments
///
/// This proof needs to be sent to the verifier, who will use it to reveal the plaintext bytes of
/// the transcript.
#[derive(Debug, Default)]
pub struct TranscriptProof {
    pub(crate) sent: RangeSet<usize>,
    sent_decoded_values: Vec<Value>,

    pub(crate) recv: RangeSet<usize>,
    recv_decoded_values: Vec<Value>,
}

impl TranscriptProof {
    /// Collects the transcript parts which are to be revealed
    ///
    /// # Arguments
    /// * `ranges` - The ranges to reveal
    /// * `direction` - The direction of the transcript
    pub fn reveal_ranges(
        &mut self,
        ranges: RangeSet<usize>,
        direction: Direction,
    ) -> Result<(), TranscriptProofError> {
        if ranges.is_empty() {
            return Err(TranscriptProofError::EmptyRange);
        }
        match direction {
            Direction::Sent => self.sent = self.sent.union(&ranges),
            Direction::Received => self.recv = self.recv.union(&ranges),
        };

        Ok(())
    }

    /// Set the decoding values for the transcript
    pub fn set_decoding(
        &mut self,
        mut decoding_values: Vec<Value>,
    ) -> Result<(), TranscriptProofError> {
        let recv_values = decoding_values.split_off(self.sent.len());

        // Verify the decoded values lengths
        if decoding_values.len() != self.sent.len() {
            return Err(TranscriptProofError::DecodedValuesLength {
                expected: self.sent.len(),
                actual: decoding_values.len(),
            });
        }
        if recv_values.len() != self.recv.len() {
            return Err(TranscriptProofError::DecodedValuesLength {
                expected: self.recv.len(),
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
    pub fn reconstruct(
        &self,
        sent_len: usize,
        recv_len: usize,
    ) -> Result<(RedactedTranscript, RedactedTranscript), TranscriptProofError> {
        let sent_redacted = RedactedTranscript::new(
            sent_len,
            ids_to_transcript_slice(&self.sent, self.sent_decoded_values.as_slice()),
        );
        let recv_redacted = RedactedTranscript::new(
            recv_len,
            ids_to_transcript_slice(&self.recv, self.recv_decoded_values.as_slice()),
        );

        Ok((sent_redacted, recv_redacted))
    }

    /// Returns an iterator over the ids
    pub fn iter_ids(
        &self,
        tx_transcript_id: impl Into<String>,
        rx_transcript_id: impl Into<String>,
    ) -> impl Iterator<Item = String> + '_ {
        let tx_transcript_id = tx_transcript_id.into();
        let rx_transcript_id = rx_transcript_id.into();

        let sent_labeled = self
            .sent
            .iter()
            .map(move |s| format!("{}/{}", tx_transcript_id, s));

        let recv_labeled = self
            .recv
            .iter()
            .map(move |s| format!("{}/{}", rx_transcript_id, s));

        sent_labeled.chain(recv_labeled)
    }
}

impl From<DecodingInfo> for TranscriptProof {
    fn from(value: DecodingInfo) -> Self {
        Self {
            sent: value.sent_ids,
            sent_decoded_values: vec![],
            recv: value.recv_ids,
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

/// An error type for [TranscriptProof].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum TranscriptProofError {
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
    fn test_transcript_proof() {
        let proof = build_test_proof();

        assert_eq!(
            proof.sent,
            RangeSet::from(2..5_usize).union(&(5..8)).union(&(8..9))
        );
        assert_eq!(proof.recv, RangeSet::from(0..3));
    }

    #[test]
    fn test_transcript_proof_iter_ids() {
        let proof = build_test_proof();
        let value_refs = proof.iter_ids("tx", "rx").collect::<Vec<String>>();

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
    fn test_transcript_proof_set_decoding() {
        let mut proof = build_test_proof();
        let decoding_values = build_test_decoding_values();
        proof.set_decoding(decoding_values.clone()).unwrap();

        assert_eq!(proof.sent_decoded_values, decoding_values[..7]);
        assert_eq!(proof.recv_decoded_values, decoding_values[7..]);
    }

    #[test]
    fn test_transcript_proof_verify() {
        let mut proof = build_test_proof();
        let decoding_values = build_test_decoding_values();
        proof.set_decoding(decoding_values.clone()).unwrap();

        let (sent, received) = proof.reconstruct(10, 12).unwrap();

        assert_eq!(sent.data(), &[0, 0, 1, 2, 3, 4, 5, 6, 7, 0]);
        assert_eq!(received.data(), &[8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(sent.authed(), &RangeSet::from(2..9));
        assert_eq!(received.authed(), &RangeSet::from(0..3));

        assert_eq!(sent.redacted(), &RangeSet::from(0..2).union(&(9..10)));
        assert_eq!(received.redacted(), &RangeSet::from(3..12));
    }

    fn build_test_proof() -> TranscriptProof {
        let mut proof = TranscriptProof::default();
        proof.reveal_ranges((2..5).into(), Direction::Sent).unwrap();
        proof
            .reveal_ranges(RangeSet::from(5..8).union(&(8..9)), Direction::Sent)
            .unwrap();
        proof
            .reveal_ranges((0..3).into(), Direction::Received)
            .unwrap();
        proof
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
