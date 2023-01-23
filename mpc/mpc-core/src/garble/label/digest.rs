use super::Label;

use crate::utils::blake3;

/// Digest of active wire labels
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelsDigest(pub(crate) [u8; 32]);

impl LabelsDigest {
    /// Creates new labels digest
    pub fn new<I>(labels: I) -> Self
    where
        I: IntoIterator<Item = Label>,
    {
        let bytes: Vec<u8> = labels
            .into_iter()
            .map(|label| label.into_inner().to_be_bytes())
            .flatten()
            .collect();
        Self(blake3(&bytes))
    }

    /// Returns digest from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
