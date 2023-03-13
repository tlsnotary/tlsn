use crate::{handshake_summary::HandshakeSummary, LabelSeed};
use serde::Serialize;

#[derive(Clone, Serialize, Default)]
pub struct SessionHeader {
    /// A PRG seeds from which to generate garbled circuit active labels, see
    /// [crate::commitment::CommitmentType::labels_blake3]
    label_seed: LabelSeed,

    /// The root of the Merkle tree of all the commitments. The User must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the User to hide from the Notary the exact amount of commitments thus
    /// increasing User privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the User.
    merkle_root: [u8; 32],

    handshake_summary: HandshakeSummary,

    /// Notary's signature over the [crate::signed::Signed] portion of this doc
    signature: Option<Vec<u8>>,
}

impl SessionHeader {
    pub fn new(
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        handshake_summary: HandshakeSummary,
        signature: Option<Vec<u8>>,
    ) -> Self {
        Self {
            label_seed,
            merkle_root,
            handshake_summary,
            signature,
        }
    }

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }

    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    pub fn handshake_summary(&self) -> &HandshakeSummary {
        &self.handshake_summary
    }

    pub fn signature(&self) -> &Option<Vec<u8>> {
        &self.signature
    }
}
