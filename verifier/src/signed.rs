use super::{tls_doc::EphemeralECPubkey, Error, HashCommitment, LabelSeed, ValidatedDoc};
use serde::Serialize;

#[derive(Clone, Serialize)]
// TLS-related data which is signed by Notary
pub struct SignedTLS {
    // notarization time against which the TLS Certificate validity is checked
    time: u64,
    // ephemeral pubkey for ECDH key exchange
    ephemeral_ec_pubkey: EphemeralECPubkey,
    /// User's commitment to [super::tls_doc::CommittedTLS]
    commitment_to_tls: HashCommitment,
}

impl SignedTLS {
    pub fn new(
        time: u64,
        ephemeral_ec_pubkey: EphemeralECPubkey,
        commitment_to_tls: HashCommitment,
    ) -> Self {
        Self {
            time,
            ephemeral_ec_pubkey,
            commitment_to_tls,
        }
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn ephemeral_ec_pubkey(&self) -> &EphemeralECPubkey {
        &self.ephemeral_ec_pubkey
    }

    pub fn commitment_to_tls(&self) -> &HashCommitment {
        &self.commitment_to_tls
    }
}

/// All the data which the Notary signs
#[derive(Clone, Serialize)]
pub struct Signed {
    tls: SignedTLS,
    // see comments in [crate::doc::VerifiedDoc] for details about the fields below
    /// PRG seed from which garbled circuit labels are generated
    label_seed: LabelSeed,
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

    pub fn serialize(self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }

    pub fn tls(&self) -> &SignedTLS {
        &self.tls
    }

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }

    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }
}

/// Extracts relevant fields from the VerifierDoc. Those are the fields
/// which the Notary signs
impl std::convert::From<&ValidatedDoc> for Signed {
    fn from(doc: &ValidatedDoc) -> Self {
        Signed::new(
            doc.tls_doc().signed_tls().clone(),
            *doc.label_seed(),
            *doc.merkle_root(),
        )
    }
}
