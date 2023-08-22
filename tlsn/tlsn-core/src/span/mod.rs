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
    fn span_request(&mut self, request: &[u8]) -> Result<Vec<Range<usize>>, SpanError>;
    /// Identify byte ranges in the response to commit to
    fn span_response(&mut self, response: &[u8]) -> Result<Vec<Range<usize>>, SpanError>;
}

/// A Spanner that commits to the entire request and response
pub struct TotalSpanner;

impl SpanCommit for TotalSpanner {
    fn span_request(&mut self, request: &[u8]) -> Result<Vec<Range<usize>>, SpanError> {
        Ok(vec![Range {
            start: 0,
            end: request.len(),
        }])
    }

    fn span_response(&mut self, response: &[u8]) -> Result<Vec<Range<usize>>, SpanError> {
        Ok(vec![Range {
            start: 0,
            end: response.len(),
        }])
    }
}

/// Inverts a set of ranges, i.e. returns the complement of the ranges
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
    let mut inverted = vec![Range { start: 0, end: len }];

    for range in ranges.iter() {
        let inv = inverted
            .iter_mut()
            .find(|inv| range.start >= inv.start)
            .unwrap();

        let original_len = inv.end;
        inv.end = range.start;

        inverted.push(Range {
            start: range.end,
            end: original_len,
        });
    }

    Ok(inverted)
}

/// An error that can occur during span creation
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum SpanError {
    #[error("Error during parsing")]
    ParseError,
    #[error("Found invalid ranges")]
    InvalidRange,
    #[error("Custom error: {0}")]
    Custom(String),
}
