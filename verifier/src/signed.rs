use crate::{tls_doc::EphemeralECPubkey, HashCommitment, LabelSeed, VerifierDoc};
use serde::Serialize;

#[derive(Clone, Serialize)]
// TLS-related struct which is signed by Notary
pub struct SignedTLS {
    // notarization time against which the TLS Certificate validity is checked
    pub time: u64,
    pub ephemeralECPubkey: EphemeralECPubkey,
    /// User's commitment to [crate::tls_doc::CommittedTLS]
    pub commitment_to_TLS: HashCommitment,
}

impl SignedTLS {
    pub fn new(
        time: u64,
        ephemeralECPubkey: EphemeralECPubkey,
        commitment_to_TLS: HashCommitment,
    ) -> Self {
        Self {
            time,
            ephemeralECPubkey,
            commitment_to_TLS,
        }
    }
}

/// All the data which the Notary signed
#[derive(Clone, Serialize)]
pub struct Signed {
    tls: SignedTLS,
    /// see comments in [crate::VerifierDoc] about the fields below
    pub label_seed: LabelSeed,
    /// Merkle root of all the commitments
    merkle_root: [u8; 32],
}

impl Signed {
    /// Creates a new struct to be signed by the Notary
    pub fn new(tls: SignedTLS, label_seed: LabelSeed, merkle_root: [u8; 32]) -> Self {
        Self {
            tls,
            label_seed,
            merkle_root,
        }
    }
}

/// Extracts relevant fields from the VerifierDoc. Those are the fields
/// which the Notary signs
impl std::convert::From<&VerifierDoc> for Signed {
    fn from(doc: &VerifierDoc) -> Self {
        Signed::new(
            doc.tls_doc.signed_tls.clone(),
            doc.label_seed.clone(),
            doc.merkle_root.clone(),
        )
    }
}
