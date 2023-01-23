use super::{tls_doc::EphemeralECPubkey, Error, HashCommitment, LabelSeed, VerifierDoc};
use serde::Serialize;

#[derive(Clone, Serialize)]
// TLS-related data which is signed by Notary
pub struct SignedTLS {
    // notarization time against which the TLS Certificate validity is checked
    time: u64,
    // ephemeral pubkey for ECDH key exchange
    ephemeralECPubkey: EphemeralECPubkey,
    /// User's commitment to [super::tls_doc::CommittedTLS]
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

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn ephemeralECPubkey(&self) -> &EphemeralECPubkey {
        &self.ephemeralECPubkey
    }
}

/// All the data which the Notary signs
#[derive(Clone, Serialize)]
pub struct Signed {
    pub tls: SignedTLS,
    // see comments in [crate::VerifierDoc] for details about the fields below
    /// PRG seed from which garbled circuit labels are generated
    pub label_seed: LabelSeed,
    /// Merkle root of all the commitments
    pub merkle_root: [u8; 32],
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

    pub fn serialize(self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }
}

/// Extracts relevant fields from the VerifierDoc. Those are the fields
/// which the Notary signs
impl std::convert::From<&VerifierDoc> for Signed {
    fn from(doc: &VerifierDoc) -> Self {
        Signed::new(
            doc.tls_doc().signed_tls().clone(),
            *doc.label_seed(),
            *doc.merkle_root(),
        )
    }
}
