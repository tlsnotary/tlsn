//! This module provides tooling to create spanning information for the [transcripts](crate::transcript::Transcript).
//!
//! When creating a [NotarizedSession](crate::NotarizedSession), the
//! [SessionData](crate::SessionData) inside contains the plaintext of the request and response.
//! The prover can decide to only commit to a subset of these bytes in order to withhold content
//! from the verifier. Consumers of this crate can implement the [SpanCommit] trait to come up with
//! their own approach for identifying the byte ranges which shall be committed to.

use std::ops::Range;

pub mod http;
pub mod json;

/// A trait for identifying byte ranges in the request and response for which commitments will be
/// created
pub trait SpanCommit {
    /// Identify byte ranges in the request to commit to
    fn span_request(&mut self, request: &[u8]) -> Vec<Range<usize>>;
    /// Identify byte ranges in the response to commit to
    fn span_response(&mut self, response: &[u8]) -> Vec<Range<usize>>;
}

pub fn invert_ranges(
    ranges: Vec<Range<usize>>,
    len: usize,
) -> Result<Vec<Range<usize>>, SpanError> {
    for range in ranges.iter() {
        // Check that there is no invalid or empty range
        if range.start >= range.end {
            return Err(SpanError::InvalidRange);
        }

        // Check that ranges are not out of bounds
        if range.start >= len || range.end > len {
            return Err(SpanError::InvalidRange);
        }

        // Check that ranges are not overlapping
        if ranges
            .iter()
            .any(|r| r.start < range.end && r.end > range.start)
        {
            return Err(SpanError::InvalidRange);
        }
    }

    // Now invert ranges
    let mut inverted = (0..len).collect::<Vec<usize>>();
}

/// An error that can occur during span creation
#[derive(Debug, thiserror::Error)]
pub enum SpanError {
    /// The request or response could not be parsed
    #[error("Error during parsing")]
    ParseError,
    #[error("Found invalid ranges")]
    InvalidRange,
}
