use crate::{
    error::Error, handshake_summary::HandshakeSummary, merkle::MerkleRoot, pubkey::PubKey,
    signature::Signature, signer::Signer, SessionArtifacts,
};
use mpc_garble_core::ChaChaEncoder;
use serde::{Deserialize, Serialize};

/// An authentic session header from the Notary
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionHeader {
    /// A PRG seeds used to generate encodings for the plaintext
    encoder_seed: [u8; 32],

    /// The root of the Merkle tree of all the commitments. The User must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the User to hide from the Notary the exact amount of commitments thus
    /// increasing User privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the User.
    merkle_root: MerkleRoot,

    /// Bytelength of all data which was sent to the webserver
    sent_len: u32,
    /// Bytelength of all data which was received from the webserver
    recv_len: u32,

    handshake_summary: HandshakeSummary,
}

impl SessionHeader {
    pub fn new(
        encoder_seed: [u8; 32],
        merkle_root: [u8; 32],
        sent_len: u32,
        recv_len: u32,
        handshake_summary: HandshakeSummary,
    ) -> Self {
        Self {
            encoder_seed,
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
            _ => Err(Error::MalformedSessionHeaderMsg),
        }
    }

    pub fn sign(&self, signer: &Signer) -> Result<Signature, Error> {
        signer.sign(self)
    }

    /// Check this header against User's artifacts
    pub fn check_artifacts(&self, artifacts: &SessionArtifacts) -> Result<(), Error> {
        if self.handshake_summary.time() - artifacts.time() > 300
            || self.merkle_root != artifacts.merkle_tree().root()
            || &self.encoder_seed != artifacts.encoder_seed()
            || artifacts
                .handshake_data_decommitment()
                .verify(self.handshake_summary.handshake_commitment())
                .is_err()
            || self.handshake_summary.ephemeral_ec_pubkey() != artifacts.ephem_key()
        {
            return Err(Error::WrongSessionHeader);
        }
        Ok(())
    }

    pub fn encoder(&self) -> ChaChaEncoder {
        ChaChaEncoder::new(self.encoder_seed)
    }

    pub fn label_seed(&self) -> &[u8; 32] {
        &self.encoder_seed
    }

    pub fn merkle_root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    pub fn handshake_summary(&self) -> &HandshakeSummary {
        &self.handshake_summary
    }

    pub fn sent_len(&self) -> u32 {
        self.sent_len
    }

    pub fn recv_len(&self) -> u32 {
        self.recv_len
    }
}

#[derive(Clone, Serialize, Deserialize)]
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

    /// Returns the session header only if the signature is not present, otherwise if a signature
    /// is present it is an error to call this method. Instead `.verify()` should be called.
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
