use crate::{
    encoder::ChaChaEncoder, error::Error, handshake_summary::HandshakeSummary, pubkey::PubKey,
    session_artifacts::SessionArtifacts, signature::Signature, signer::Signer,
};
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

    /// Bytelength of all data which was sent to the webserver
    sent_len: u32,
    /// Bytelength of all data which was received from the webserver
    recv_len: u32,

    handshake_summary: HandshakeSummary,
}

impl SessionHeader {
    pub fn new(
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        sent_len: u32,
        recv_len: u32,
        handshake_summary: HandshakeSummary,
    ) -> Self {
        Self {
            label_seed,
            merkle_root,
            sent_len,
            recv_len,
            handshake_summary,
        }
    }

    pub fn from_msg(msg: &SessionHeaderMsg, pubkey: Option<&PubKey>) -> Result<Self, Error> {
        match (pubkey, &msg.signature) {
            (Some(pubkey), Some(_)) => msg.verify(pubkey),
            (None, None) => msg.get_header(),
            _ => Err(Error::InternalError),
        }
    }

    pub fn sign(&self, signer: &Signer) -> Result<Signature, Error> {
        signer.sign(self)
    }

    pub fn check_artifacts(&self, artifacts: &SessionArtifacts) -> Result<(), Error> {
        if self.handshake_summary.time() - artifacts.time() > 300
            || &self.merkle_root != artifacts.merkle_root()
            || &self.label_seed != artifacts.label_seed()
            || self.handshake_summary.handshake_commitment() != artifacts.handshake_commitment()
        // TODO impl eq check for pubkey
        // || self.handshake_summary.ephemeral_ec_pubkey() != artifacts.ephem_key()
        {
            return Err(Error::InternalError);
        }
        Ok(())
    }

    pub fn encoder(&self) -> ChaChaEncoder {
        ChaChaEncoder::new(self.label_seed)
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

#[derive(Clone, Serialize, Default)]
pub struct SessionHeaderMsg {
    header: SessionHeader,
    /// signature over `header`
    signature: Option<Signature>,
}

impl SessionHeaderMsg {
    pub fn new(header: &SessionHeader, signature: Option<Signature>) -> Self {
        Self {
            header: header.clone(),
            signature,
        }
    }

    /// Verifies the signature over the header against the public key. This is only called when we
    /// know that `signature` is Some().
    ///
    /// Returns the verified header
    fn verify(&self, pubkey: &PubKey) -> Result<SessionHeader, Error> {
        let sig = match &self.signature {
            Some(sig) => sig,
            _ => return Err(Error::InternalError),
        };

        match (sig, pubkey) {
            // signature and pubkey types must match
            (Signature::P256(_), PubKey::P256(_)) => {
                pubkey.verify(&self.header, sig)?;
            }
        }

        Ok(self.header.clone())
    }

    /// Returns the session header only if the signature is not present
    fn get_header(&self) -> Result<SessionHeader, Error> {
        match &self.signature {
            Some(_) => Ok(self.header.clone()),
            _ => Err(Error::SignatureNotExpected),
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}
