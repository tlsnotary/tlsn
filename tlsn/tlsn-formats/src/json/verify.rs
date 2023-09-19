use std::ops::Range;

use spansy::{json::JsonValue, Spanned};
use tlsn_core::RedactedTranscript;
use utils::range::RangeSubset;

pub struct JsonVerifier<'a> {
    transcript: &'a RedactedTranscript,
    value: &'a JsonValue,
}

impl<'a> JsonVerifier<'a> {
    pub(crate) fn new(transcript: &'a RedactedTranscript, value: &'a JsonValue) -> Self {
        Self { transcript, value }
    }

    /// Returns the value at the given path, if it exists and was not redacted.
    pub fn path(&self, path: &str) -> Option<&[u8]> {
        let value = self.value.get(path)?;
        let range = value.span().range();
        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    fn is_auth(&self, range: &Range<usize>) -> bool {
        range.is_subset(self.transcript.authed())
    }
}
