pub mod dual;

use crate::{
    garble::{OutputLabels, WireLabel},
    utils::sha256,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutputCheck(pub(crate) [u8; 32]);

#[derive(Clone, PartialEq)]
pub struct OutputCommit(pub(crate) [u8; 32]);

impl OutputCheck {
    /// Creates new output check
    ///
    /// This output check is a hash of the output wire labels from the peer's circuit along with the
    /// expected labels from the callers garbled circuit. The expected labels are determined using
    /// the decoded output values from evaluating the peer's garbled circuit.
    pub fn new(labels: (&[OutputLabels<WireLabel>], &[OutputLabels<WireLabel>])) -> Self {
        let bytes: Vec<u8> = labels
            .0
            .iter()
            .chain(labels.1.iter())
            .map(|labels| labels.to_be_bytes())
            .flatten()
            .collect();
        Self(sha256(&bytes))
    }
}

impl OutputCommit {
    pub fn new(check: &OutputCheck) -> Self {
        Self(sha256(&check.0))
    }
}
