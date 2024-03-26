use utils::range::{RangeSet, ToRangeSet};

use crate::{
    conn::TranscriptLength,
    encoding::{EncodingProvider, EncodingTree},
    hash::HashAlgorithm,
    transcript::SubsequenceIdx,
    Direction,
};

/// Encoding tree builder error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingTreeBuilderError {
    /// Attempted to commit to an empty range.
    #[error("attempted to commit to an empty range")]
    EmptyRange,
    /// Attempted to commit to a range that exceeds the transcript length.
    #[error(
        "attempted to commit to a range that exceeds the transcript length: \
        {input_end} > {transcript_length}"
    )]
    OutOfBounds {
        /// The end of the input range.
        input_end: usize,
        /// The transcript length.
        transcript_length: usize,
        /// The direction of the transcript.
        direction: Direction,
    },
    /// The encoding provider is missing the encoding for the given range.
    #[error(
        "the encoding provider is missing the encoding for the given range: \
        {direction:?} {ranges:?}"
    )]
    MissingEncoding {
        /// The input ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
    },
}

/// A builder for an encoding tree.
pub struct EncodingTreeBuilder {
    provider: Box<dyn EncodingProvider>,
    tree: EncodingTree,
    transcript_length: TranscriptLength,
}

opaque_debug::implement!(EncodingTreeBuilder);

impl EncodingTreeBuilder {
    /// Creates a new encoding tree builder.
    pub fn new(
        provider: Box<dyn EncodingProvider>,
        transcript_length: TranscriptLength,
        alg: HashAlgorithm,
    ) -> Self {
        Self {
            provider,
            tree: EncodingTree::new(alg),
            transcript_length,
        }
    }

    /// Commits the given ranges to the encoding tree.
    pub fn commit_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, EncodingTreeBuilderError> {
        self.commit(ranges, Direction::Sent)
    }

    /// Commits the given ranges to the encoding tree.
    pub fn commit_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, EncodingTreeBuilderError> {
        self.commit(ranges, Direction::Received)
    }

    /// Commits the given ranges to the encoding tree.
    pub fn commit(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, EncodingTreeBuilderError> {
        let ranges = ranges.to_range_set();
        let end = ranges.end().ok_or(EncodingTreeBuilderError::EmptyRange)?;
        let len = match direction {
            Direction::Sent => self.transcript_length.sent as usize,
            Direction::Received => self.transcript_length.received as usize,
        };

        if end > len {
            return Err(EncodingTreeBuilderError::OutOfBounds {
                input_end: end,
                transcript_length: len,
                direction,
            });
        }

        let encoding = self
            .provider
            .provide_ranges(ranges.clone(), direction)
            .ok_or_else(|| EncodingTreeBuilderError::MissingEncoding {
                ranges: ranges.clone(),
                direction,
            })?;

        self.tree
            .add_leaf(SubsequenceIdx { ranges, direction }, encoding);

        Ok(self)
    }

    /// Builds the encoding tree.
    pub fn build(self) -> Result<EncodingTree, EncodingTreeBuilderError> {
        Ok(self.tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::provider;
    use tlsn_fixtures::http::{request::POST_JSON, response::OK_JSON};

    fn builder() -> EncodingTreeBuilder {
        let provider = Box::new(provider(POST_JSON, OK_JSON));
        let transcript_length = TranscriptLength {
            sent: POST_JSON.len() as u32,
            received: OK_JSON.len() as u32,
        };
        EncodingTreeBuilder::new(provider, transcript_length, HashAlgorithm::Blake3)
    }

    #[test]
    fn test_encoding_tree_builder() {
        let mut builder = builder();

        builder
            .commit_sent(&(0..POST_JSON.len()))
            .unwrap()
            .commit_recv(&(0..OK_JSON.len()))
            .unwrap();

        let tree = builder.build().unwrap();

        assert!(tree.contains(&SubsequenceIdx {
            ranges: (0..POST_JSON.len()).into(),
            direction: Direction::Sent,
        }));
        assert!(tree.contains(&SubsequenceIdx {
            ranges: (0..OK_JSON.len()).into(),
            direction: Direction::Received,
        }));
    }

    #[test]
    fn test_encoding_tree_builder_multiple_ranges() {
        let mut builder = builder();

        builder
            .commit_sent(&(0..1))
            .unwrap()
            .commit_sent(&(1..POST_JSON.len()))
            .unwrap()
            .commit_recv(&(0..1))
            .unwrap()
            .commit_recv(&(1..OK_JSON.len()))
            .unwrap();

        let tree = builder.build().unwrap();

        assert!(tree.contains(&SubsequenceIdx {
            ranges: (0..1).into(),
            direction: Direction::Sent,
        }));
        assert!(tree.contains(&SubsequenceIdx {
            ranges: (1..POST_JSON.len()).into(),
            direction: Direction::Sent,
        }));
        assert!(tree.contains(&SubsequenceIdx {
            ranges: (0..1).into(),
            direction: Direction::Received,
        }));
        assert!(tree.contains(&SubsequenceIdx {
            ranges: (1..OK_JSON.len()).into(),
            direction: Direction::Received,
        }));
    }

    #[test]
    fn test_encoding_tree_builder_out_of_bounds() {
        let mut builder = builder();

        let result = builder.commit_sent(&(0..POST_JSON.len() + 1)).unwrap_err();
        assert!(matches!(
            result,
            EncodingTreeBuilderError::OutOfBounds { .. }
        ));

        let result = builder.commit_recv(&(0..OK_JSON.len() + 1)).unwrap_err();
        assert!(matches!(
            result,
            EncodingTreeBuilderError::OutOfBounds { .. }
        ));
    }

    #[test]
    fn test_encoding_tree_missing_encoding() {
        let provider = Box::new(provider(&[], &[]));
        let transcript_length = TranscriptLength {
            sent: 8,
            received: 8,
        };
        let mut builder =
            EncodingTreeBuilder::new(provider, transcript_length, HashAlgorithm::Blake3);

        let result = builder.commit_sent(&(0..8)).unwrap_err();
        assert!(matches!(
            result,
            EncodingTreeBuilderError::MissingEncoding { .. }
        ));

        let result = builder.commit_recv(&(0..8)).unwrap_err();
        assert!(matches!(
            result,
            EncodingTreeBuilderError::MissingEncoding { .. }
        ));
    }
}
