use crate::{error::Error, substrings_commitment::Direction};
use serde::Serialize;

/// A transcript consists of all bytes which were sent and all bytes which were received
#[derive(Default, Serialize)]
pub struct Transcript {
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Transcript {
    pub fn new(sent: Vec<u8>, received: Vec<u8>) -> Self {
        Self { sent, received }
    }

    pub fn get_bytes_in_ranges(
        &self,
        ranges: &[TranscriptRange],
        direction: &Direction,
    ) -> Result<Vec<u8>, Error> {
        // TODO
        Ok(vec![0u8; 32])
    }

    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

    pub fn received(&self) -> &[u8] {
        &self.received
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
/// A non-empty half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct TranscriptRange {
    start: u32,
    end: u32,
}

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
}

/// Authenticated slice of data
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
