use p256::{
    self,
    ecdsa::{signature::Verifier, Signature},
    EncodedPoint,
};

use super::Error;

pub enum KeyType {
    P256,
}

/// A public key used by the Notary to sign the notarization session
pub enum PubKey {
    P256(p256::ecdsa::VerifyingKey),
}

impl PubKey {
    /// Constructs pubkey from bytes
    pub fn from_bytes(typ: KeyType, bytes: &[u8]) -> Result<Self, Error> {
        match typ {
            KeyType::P256 => {
                let point = match EncodedPoint::from_bytes(bytes) {
                    Ok(point) => point,
                    Err(_) => return Err(Error::InternalError),
                };
                let vk = match p256::ecdsa::VerifyingKey::from_encoded_point(&point) {
                    Ok(vk) => vk,
                    Err(_) => return Err(Error::InternalError),
                };
                Ok(PubKey::P256(vk))
            }
            _ => Err(Error::InternalError),
        }
    }

    /// Verifies a signature `sig` for the message `msg`
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            PubKey::P256(key) => {
                let signature = match Signature::from_der(sig) {
                    Ok(sig) => sig,
                    Err(_) => return Err(Error::SignatureVerificationError),
                };
                match key.verify(msg, &signature) {
                    Ok(_) => Ok(()),
                    Err(_) => return Err(Error::SignatureVerificationError),
                }
            }
            _ => Err(Error::InternalError),
        }
    }
}
