use super::{state, Labels};
use mpc_circuits::WireGroup;

use crate::utils::blake3;

/// Digest of active wire labels
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelsDigest(pub(crate) [u8; 32]);

impl LabelsDigest {
    /// Creates new labels digest
    pub fn new<G: WireGroup>(labels: &[Labels<G, state::Active>]) -> Self {
        let bytes: Vec<u8> = labels
            .iter()
            .map(|labels| labels.state.to_be_bytes())
            .flatten()
            .collect();
        Self(blake3(&bytes))
    }

    /// Returns digest from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
