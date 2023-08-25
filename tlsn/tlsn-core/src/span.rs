//! This module provides tooling to create spanning information for the [transcripts](crate::transcript::Transcript).
//!
//! When creating a [NotarizedSession](crate::NotarizedSession), the
//! [SessionData](crate::SessionData) inside contains the plaintext of the request and response.
//! The prover can decide to only commit to a subset of these bytes in order to withhold content
//! from the verifier. Consumers of this crate can implement the [SpanCommit] trait to come up with
//! their own approach for identifying the byte ranges which shall be committed to.

use std::ops::Range;

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
    for (k, range) in ranges.iter().enumerate() {
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
            .enumerate()
            .any(|(l, r)| k != l && r.start < range.end && r.end > range.start)
        {
            return Err(SpanError::InvalidRange);
        }
    }

    // Now invert ranges
    let mut inverted = vec![Range { start: 0, end: len }];

    for range in ranges.iter() {
        let inv = inverted
            .iter_mut()
            .find(|inv| range.start >= inv.start && range.end <= inv.end)
            .expect("Should have found range to invert");

        let original_end = inv.end;
        inv.end = range.start;

        inverted.push(Range {
            start: range.end,
            end: original_end,
        });
    }

    // Remove empty ranges
    inverted.retain(|r| r.start != r.end);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invert_ranges_errors() {
        let empty_range = Range { start: 0, end: 0 };
        let invalid_range = Range { start: 2, end: 1 };
        let out_of_bounds = Range { start: 4, end: 11 };

        let ranges = vec![empty_range, invalid_range, out_of_bounds];

        for range in ranges {
            assert!(invert_ranges(vec![range], 10).is_err());
        }
    }

    #[test]
    fn test_invert_ranges_overlapping() {
        let overlapping1 = vec![Range { start: 2, end: 5 }, Range { start: 4, end: 7 }];
        let overlapping2 = vec![Range { start: 2, end: 5 }, Range { start: 1, end: 4 }];
        let overlapping3 = vec![Range { start: 2, end: 5 }, Range { start: 3, end: 4 }];
        let overlapping4 = vec![Range { start: 2, end: 5 }, Range { start: 2, end: 5 }];

        // this should not be an error
        let ok1 = vec![Range { start: 2, end: 5 }, Range { start: 5, end: 8 }];
        let ok2 = vec![Range { start: 2, end: 5 }, Range { start: 7, end: 10 }];

        let overlap = vec![overlapping1, overlapping2, overlapping3, overlapping4];
        let ok = vec![ok1, ok2];

        for range in overlap {
            assert!(invert_ranges(range, 10).is_err());
        }

        for range in ok {
            assert!(invert_ranges(range, 10).is_ok());
        }
    }

    #[test]
    fn test_invert_ranges() {
        let len = 20;

        let ranges = vec![
            Range { start: 0, end: 5 },
            Range { start: 5, end: 10 },
            Range { start: 12, end: 16 },
            Range { start: 18, end: 20 },
        ];

        let expected = vec![Range { start: 10, end: 12 }, Range { start: 16, end: 18 }];

        assert_eq!(invert_ranges(ranges, len).unwrap(), expected);
    }
}
