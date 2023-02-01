use super::{tls_handshake::EphemeralECPubkey, Error, HashCommitment, LabelSeed, ValidatedDoc};
use serde::Serialize;

#[derive(Clone, Serialize)]
/// TLS handshake-related data which is signed by Notary
pub struct SignedHandshake {
    /// notarization time against which the TLS Certificate validity is checked
    time: u64,
    /// ephemeral pubkey for ECDH key exchange
    ephemeral_ec_pubkey: EphemeralECPubkey,
    /// User's commitment to [super::tls_doc::HandshakeData]
    handshake_commitment: HashCommitment,
}

impl SignedHandshake {
    pub fn new(
        time: u64,
        ephemeral_ec_pubkey: EphemeralECPubkey,
        handshake_commitment: HashCommitment,
    ) -> Self {
        Self {
            time,
            ephemeral_ec_pubkey,
            handshake_commitment,
        }
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn ephemeral_ec_pubkey(&self) -> &EphemeralECPubkey {
        &self.ephemeral_ec_pubkey
    }

    pub fn handshake_commitment(&self) -> &HashCommitment {
        &self.handshake_commitment
    }
}

/// All the data which the Notary signs
/// (see comments to fields with the same name in [crate::doc::VerifiedDoc] for details)
#[derive(Clone, Serialize)]
pub struct Signed {
    tls: SignedHandshake,
    /// PRG seed from which garbled circuit labels are generated
    label_seed: LabelSeed,
    /// Merkle root of all the commitments
    merkle_root: [u8; 32],
}

impl Signed {
    /// Creates a new struct to be signed by the Notary
    pub fn new(tls: SignedHandshake, label_seed: LabelSeed, merkle_root: [u8; 32]) -> Self {
        Self {
            tls,
            label_seed,
            merkle_root,
        }
    }

    pub fn serialize(self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
    }

    pub fn tls(&self) -> &SignedHandshake {
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
            doc.tls_handshake().signed_handshake().clone(),
            *doc.label_seed(),
            *doc.merkle_root(),
        )
    }
}
