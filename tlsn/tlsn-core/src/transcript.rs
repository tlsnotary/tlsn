use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::ops::Range;

/// A transcript contains a subset of bytes from a TLS session
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Transcript {
    id: String,
    data: Vec<u8>,
}

impl Transcript {
    pub fn new(id: &str, data: Vec<u8>) -> Self {
        Self {
            id: id.to_string(),
            data,
        }
    }

    /// Extends the transcript with the given data
    pub fn extend(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    /// Returns the value ID for each byte in the provided range
    pub fn get_ids(&self, range: &Range<u32>) -> Vec<String> {
        range
            .clone()
            .map(|idx| format!("{}/{}", self.id, idx))
            .collect::<Vec<_>>()
    }

    /// Returns a concatenated bytestring located in the given ranges of the transcript.
    ///
    /// Is only called with non-empty well-formed `ranges`
    pub(crate) fn get_bytes_in_ranges(&self, ranges: &[Range<u32>]) -> Result<Vec<u8>, Error> {
        // at least one range must be present
        if ranges.is_empty() {
            return Err(Error::InternalError);
        }

        let mut dst: Vec<u8> = Vec::new();
        for r in ranges {
            if r.end as usize >= self.data.len() {
                // range bounds must be within `src` length
                return Err(Error::InternalError);
            } else {
                dst.extend(&self.data[r.start as usize..r.end as usize]);
            }
        }

        Ok(dst)
    }

    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Authenticated slice of [Transcript]. The [Direction] should be infered from some outer context.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: Range<u32>,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: Range<u32>, data: Vec<u8>) -> Self {
        Self { range, data }
    }

    pub fn range(&self) -> &Range<u32> {
        &self.range
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
/// A [Transcript] consists of a stream of bytes which were sent to the server
/// and a stream of bytes which were received from the server . The User creates
/// separate commitments to bytes in each direction.
pub enum Direction {
    Sent,
    Received,
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn transcripts() -> (Transcript, Transcript) {
        let sent = "data sent 123456789".as_bytes().to_vec();
        let recv = "data received 987654321".as_bytes().to_vec();
        (Transcript::new("tx", sent), Transcript::new("rx", recv))
    }

    #[rstest]
    fn test_get_bytes_in_ranges_ok(transcripts: (Transcript, Transcript)) {
        let (sent, recv) = transcripts;

        let range1 = Range { start: 2, end: 4 };
        let range2 = Range { start: 10, end: 15 };

        let expected = "ta12345".as_bytes().to_vec();
        assert_eq!(
            expected,
            sent.get_bytes_in_ranges(&[range1.clone(), range2.clone()])
                .unwrap()
        );

        let expected = "taved 9".as_bytes().to_vec();
        assert_eq!(
            expected,
            recv.get_bytes_in_ranges(&[range1, range2]).unwrap()
        );
    }

    #[rstest]
    fn test_get_bytes_in_ranges_err(transcripts: (Transcript, Transcript)) {
        let (sent, _) = transcripts;

        // no_range provided
        let err = sent.get_bytes_in_ranges(&[]);
        assert_eq!(err.unwrap_err(), Error::InternalError);

        // range larger than data length
        let bad_range = Range { start: 2, end: 40 };
        let err = sent.get_bytes_in_ranges(&[bad_range]);
        assert_eq!(err.unwrap_err(), Error::InternalError);
    }
}
