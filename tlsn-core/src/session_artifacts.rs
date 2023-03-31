use crate::{pubkey::PubKey, session_header::LabelSeed, HashCommitment};

// Various artefacts which the User holds at the end of the notarization session
pub struct SessionArtifacts {
    // time when TLS handshake was initiated
    time: u64,
    merkle_root: [u8; 32],
    label_seed: LabelSeed,
    ephem_key: PubKey,
    handshake_commitment: HashCommitment,
}

impl SessionArtifacts {
    pub fn new(
        time: u64,
        merkle_root: [u8; 32],
        label_seed: LabelSeed,
        ephem_key: PubKey,
        handshake_commitment: HashCommitment,
    ) -> Self {
        Self {
            time,
            merkle_root,
            label_seed,
            ephem_key,
            handshake_commitment,
        }
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }

    pub fn ephem_key(&self) -> &PubKey {
        &self.ephem_key
    }

    pub fn handshake_commitment(&self) -> &HashCommitment {
        &self.handshake_commitment
    }
}
