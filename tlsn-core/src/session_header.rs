use crate::{error::Error, handshake_summary::HandshakeSummary, pubkey::PubKey, signer::Signer};
use serde::Serialize;

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];

/// An authentic session header from the Notary
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
}

impl SessionHeader {
    pub fn new(
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        handshake_summary: HandshakeSummary,
    ) -> Self {
        Self {
            label_seed,
            merkle_root,
            handshake_summary,
        }
    }

    pub fn from_msg(msg: &SessionHeaderMsg, pubkey: Option<&PubKey>) -> Result<Self, Error> {
        match (pubkey, msg.signature) {
            (Some(pubkey), Some(sig)) => msg.verify(pubkey),
            (None, None) => msg.get_header(),
            _ => {
                return Err(Error::InternalError);
            }
        }
    }

    pub fn sign(self, signer: &Signer) -> Result<&[u8], Error> {
        let msg = self.serialize()?;
        let sig = signer.sign(msg);
        Ok(sig)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self).map_err(|_| Error::SerializationError)
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
}

pub struct SessionHeaderMsg {
    header: SessionHeader,
    /// signature over `header`
    signature: Option<Vec<u8>>,
}

impl SessionHeaderMsg {
    pub fn new(header: &SessionHeader, signature: Option<Vec<u8>>) -> Self {
        Self {
            header: header.clone(),
            signature,
        }
    }

    /// Verifies the signature over the header against the public key
    ///
    /// Returns the verified header
    pub fn verify(&self, pubkey: &PubKey) -> Result<SessionHeader, Error> {
        let msg = self.header.serialize()?;

        match self.signature {
            Some(signature) => {
                pubkey.verify_signature(&msg, &signature)?;
            }
            _ => {
                return Err(Error::SignatureExpected);
            }
        }

        Ok(self.header)
    }

    /// Returns the session header only if the signature is not present
    pub fn get_header(&self) -> Result<SessionHeader, Error> {
        match self.signature {
            Some(signature) => Ok(self.header),
            _ => {
                return Err(Error::SignatureNotExpected);
            }
        }
    }

    pub fn signature(&self) -> Option<Vec<u8>> {
        self.signature
    }
}
