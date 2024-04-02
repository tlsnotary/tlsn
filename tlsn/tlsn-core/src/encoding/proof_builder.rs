use std::collections::HashSet;

use utils::range::{RangeSet, ToRangeSet};

use crate::{
    encoding::{proof::EncodingProof, tree::EncodingTree},
    transcript::{SubsequenceIdx, TranscriptReveal},
    Direction, Transcript,
};

#[derive(Debug, thiserror::Error)]
pub enum EncodingProofBuilderError {
    /// Attempted to prove an empty range.
    #[error("attempted to prove an empty range")]
    EmptyRange,
    /// Attempted to prove a range that exceeds the transcript length.
    #[error("attempted to prove a range that exceeds the transcript length: {input_end} > {transcript_length}")]
    OutOfBounds {
        /// The end of the input range.
        input_end: usize,
        /// The transcript length.
        transcript_length: usize,
        /// The direction of the transcript.
        direction: Direction,
    },
    /// The encoding tree is missing the encoding for the given range.
    #[error(
        "the encoding tree is missing the encoding for the given range: {direction:?} {ranges:?}"
    )]
    MissingEncoding {
        ranges: RangeSet<usize>,
        direction: Direction,
    },
}

/// An encoding proof builder.
pub struct EncodingProofBuilder<'a> {
    tree: &'a EncodingTree,
    transcript_tx: &'a Transcript,
    transcript_rx: &'a Transcript,
    seqs: HashSet<SubsequenceIdx>,
}

impl<'a> TranscriptReveal for EncodingProofBuilder<'a> {
    type Error = EncodingProofBuilderError;

    fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, Self::Error> {
        let ranges = ranges.to_range_set();
        let transcript = match direction {
            Direction::Sent => self.transcript_tx,
            Direction::Received => self.transcript_rx,
        };

        let end = ranges.end().ok_or(EncodingProofBuilderError::EmptyRange)?;
        if end > transcript.len() {
            return Err(EncodingProofBuilderError::OutOfBounds {
                input_end: end,
                transcript_length: transcript.len(),
                direction,
            });
        }

        let seq = SubsequenceIdx { ranges, direction };
        if !self.tree.contains(&seq) {
            return Err(EncodingProofBuilderError::MissingEncoding {
                ranges: seq.ranges,
                direction: seq.direction,
            });
        }

        // We allow for duplicate subsequences to be provided,
        // but we only generate one proof.
        self.seqs.insert(seq);

        Ok(self)
    }
}

impl<'a> EncodingProofBuilder<'a> {
    /// Creates a new encoding proof builder.
    pub fn new(
        tree: &'a EncodingTree,
        transcript_tx: &'a Transcript,
        transcript_rx: &'a Transcript,
    ) -> Self {
        Self {
            tree,
            transcript_tx,
            transcript_rx,
            seqs: HashSet::default(),
        }
    }

    /// Builds the encoding proof.
    pub fn build(self) -> Result<EncodingProof, EncodingProofBuilderError> {
        let Self {
            tree,
            seqs,
            transcript_tx,
            transcript_rx,
        } = self;

        let seqs = seqs
            .into_iter()
            .map(|seq| {
                let data = match seq.direction {
                    Direction::Sent => transcript_tx.get_bytes_in_ranges(&seq.ranges),
                    Direction::Received => transcript_rx.get_bytes_in_ranges(&seq.ranges),
                };

                (seq, data)
            })
            .collect::<Vec<_>>();

        Ok(tree.proof(seqs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        conn::TranscriptLength,
        encoding::{tree_builder::EncodingTreeBuilder, EncodingCommitment},
        fixtures::{encoder_seed, provider},
        hash::HashAlgorithm,
        transcript::TranscriptCommit,
    };
    use bytes::Bytes;
    use tlsn_data_fixtures::http::{request::POST_JSON, response::OK_JSON};

    fn tree() -> EncodingTree {
        let provider = Box::new(provider(POST_JSON, OK_JSON));
        let transcript_length = TranscriptLength {
            sent: POST_JSON.len() as u32,
            received: OK_JSON.len() as u32,
        };
        let mut builder =
            EncodingTreeBuilder::new(provider, transcript_length, HashAlgorithm::Blake3);
        builder
            .commit_sent(&(2..POST_JSON.len()))
            .unwrap()
            .commit_sent(&(0..1))
            .unwrap()
            .commit_recv(&(2..OK_JSON.len()))
            .unwrap()
            .commit_recv(&(0..1))
            .unwrap();

        builder.build().unwrap()
    }

    #[test]
    fn test_encoding_proof_builder() {
        let tree = tree();
        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };
        let transcript_length = TranscriptLength {
            sent: POST_JSON.len() as u32,
            received: OK_JSON.len() as u32,
        };
        let transcript_tx = Transcript::new(Bytes::copy_from_slice(POST_JSON));
        let transcript_rx = Transcript::new(Bytes::copy_from_slice(OK_JSON));
        let mut builder = EncodingProofBuilder::new(&tree, &transcript_tx, &transcript_rx);

        builder
            .reveal_sent(&(2..POST_JSON.len()))
            .unwrap()
            .reveal_sent(&(0..1))
            .unwrap()
            .reveal_recv(&(2..OK_JSON.len()))
            .unwrap()
            .reveal_recv(&(0..1))
            .unwrap();

        let proof = builder.build().unwrap();
        let (sent, recv) = proof.verify(&transcript_length, &commitment).unwrap();

        assert_eq!(&sent.data()[..1], &POST_JSON[..1]);
        assert_eq!(&sent.data()[2..], &POST_JSON[2..]);
        assert_eq!(&recv.data()[..1], &OK_JSON[..1]);
        assert_eq!(&recv.data()[2..], &OK_JSON[2..]);
    }
}
