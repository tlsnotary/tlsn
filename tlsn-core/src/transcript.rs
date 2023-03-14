use crate::error::Error;
use serde::Serialize;

/// A transcript consists of all bytes which were sent and all bytes which were received
pub struct Transcript {
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Transcript {
    pub fn new(sent: Vec<u8>, received: Vec<u8>) -> Self {
        Self { sent, received }
    }

    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

    pub fn received(&self) -> &[u8] {
        &self.received
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
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
