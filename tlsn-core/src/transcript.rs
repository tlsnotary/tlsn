use crate::error::Error;
use serde::{Deserialize, Serialize};

/// A transcript consists of all bytes which were sent and all bytes which were received
#[derive(Default, Serialize, Deserialize)]
pub struct Transcript {
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Transcript {
    pub fn new(sent: Vec<u8>, received: Vec<u8>) -> Self {
        Self { sent, received }
    }

    /// Returns a concatenated bytestring located in the given ranges of the transcript.
    pub fn get_bytes_in_ranges(
        &self,
        ranges: &[TranscriptRange],
        direction: &Direction,
    ) -> Result<Vec<u8>, Error> {
        // at least one range must be present
        if ranges.is_empty() {
            return Err(Error::InternalError);
        }

        // pick source depending on direction
        let src = if direction == &Direction::Sent {
            &self.sent
        } else {
            &self.received
        };

        let mut dst: Vec<u8> = Vec::new();
        for r in ranges {
            if r.end() as usize >= src.len() {
                // range bounds must be within `src` length
                return Err(Error::InternalError);
            } else {
                dst.extend(&src[r.start() as usize..r.end() as usize]);
            }
        }

        Ok(dst)
    }

    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

    pub fn received(&self) -> &[u8] {
        &self.received
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
/// A non-empty half-open range of the bytes in the transcript. Range bounds are ascending
/// i.e. start < end
pub struct TranscriptRange {
    start: u32,
    end: u32,
}

#[allow(clippy::len_without_is_empty)]
impl TranscriptRange {
    pub fn new(start: u32, end: u32) -> Result<Self, Error> {
        // empty ranges are not allowed
        if start >= end {
            return Err(Error::RangeInvalid);
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn end(&self) -> u32 {
        self.end
    }

    pub fn len(&self) -> u32 {
        self.end - self.start
    }
}

/// Authenticated slice of [Transcript]. The [Direction] should be infered from some outer context.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: TranscriptRange,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: TranscriptRange, data: Vec<u8>) -> Self {
        Self { range, data }
    }

    pub fn range(&self) -> &TranscriptRange {
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
    fn transcript() -> Transcript {
        let sent = "data sent 123456789".as_bytes().to_vec();
        let recv = "data received 987654321".as_bytes().to_vec();
        Transcript::new(sent, recv)
    }

    #[rstest]
    fn test_get_bytes_in_ranges_ok(transcript: Transcript) {
        let range1 = TranscriptRange::new(2, 4).unwrap();
        let range2 = TranscriptRange::new(10, 15).unwrap();

        let expected = "ta12345".as_bytes().to_vec();
        assert_eq!(
            expected,
            transcript
                .get_bytes_in_ranges(&[range1.clone(), range2.clone()], &Direction::Sent)
                .unwrap()
        );

        let expected = "taved 9".as_bytes().to_vec();
        assert_eq!(
            expected,
            transcript
                .get_bytes_in_ranges(&[range1, range2], &Direction::Received)
                .unwrap()
        );
    }

    #[rstest]
    fn test_get_bytes_in_ranges_err(transcript: Transcript) {
        // no_range provided
        let err = transcript.get_bytes_in_ranges(&[], &Direction::Sent);
        assert_eq!(err.unwrap_err(), Error::InternalError);

        // range larger than data length
        let bad_range = TranscriptRange::new(2, 40).unwrap();
        let err = transcript.get_bytes_in_ranges(&[bad_range], &Direction::Sent);
        assert_eq!(err.unwrap_err(), Error::InternalError);
    }
}
