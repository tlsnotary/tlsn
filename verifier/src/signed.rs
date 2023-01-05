use crate::{tls_doc::EphemeralECPubkey, HashCommitment, LabelSeed, VerifierDoc};

#[derive(Clone)]
// TLS-related struct which is signed by Notary
pub struct SignedTLS {
    // notarization time against which the TLS Certificate validity is checked
    pub time: u64,
    pub ephemeralECPubkey: EphemeralECPubkey,
    /// User's commitment to [`CommittedTLS`]
    pub commitment_to_TLS: HashCommitment,
}

/// All the data which the Notary signed
#[derive(Clone)]
pub struct Signed {
    tls: SignedTLS,
    /// see comments in [crate::VerifierDoc] about the fields below
    pub label_seed: LabelSeed,
    commitment_root: [u8; 32],
}

impl Signed {
    /// Creates a new struct to be signed by the Notary
    pub fn new(tls: SignedTLS, label_seed: LabelSeed, commitment_root: [u8; 32]) -> Self {
        Self {
            tls,
            label_seed,
            commitment_root,
        }
    }

    // return a serialized struct which can be signed or verified
    pub fn serialize(&self) -> Vec<u8> {
        vec![0u8; 100]
    }

    // convert into a tbd format which can be stored on disk
    pub fn to_intermediate_format(&self) {}
}

/// Extracts relevant fields from the VerifierDoc. Those are the fields
/// which the Notary signs
impl std::convert::From<&VerifierDoc> for Signed {
    fn from(doc: &VerifierDoc) -> Self {
        Signed::new(
            doc.tls_doc.signed_tls.clone(),
            doc.labelSeed.clone(),
            doc.merkle_root.clone(),
        )
    }
}
