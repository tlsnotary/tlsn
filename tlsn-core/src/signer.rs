use crate::{
    error::Error,
    pubkey::{KeyType, PubKey, P256},
    signature::Signature,
};
use p256::ecdsa::signature::Signer as P256Signer;
use serde::Serialize;

/// Errors that can occur during operations with the signer
#[derive(Debug, thiserror::Error, PartialEq)]
#[allow(missing_docs)]
pub enum SignerError {
    #[error("Can't construct Signer from provided bytes")]
    WrongBytes,
}

pub enum Signer {
    P256(p256::ecdsa::SigningKey),
}

impl Signer {
    /// Create a new Signer of the given type from raw private key bytes
    pub fn new(typ: KeyType, bytes: &[u8]) -> Result<Self, SignerError> {
        match typ {
            KeyType::P256 => {
                let signing_key = match p256::ecdsa::SigningKey::from_bytes(bytes) {
                    Ok(key) => key,
                    Err(_) => return Err(SignerError::WrongBytes),
                };
                Ok(Signer::P256(signing_key))
            }
        }
    }

    pub fn verifying_key(&self) -> PubKey {
        match self {
            Signer::P256(signing_key) => {
                let vk = signing_key.verifying_key();
                PubKey::P256(P256::new(vk, false))
            }
        }
    }

    pub fn sign(&self, msg: &impl Serialize) -> Result<Signature, Error> {
        let msg = bincode::serialize(msg).expect("should be able to serialize");
        match self {
            Signer::P256(signing_key) => Ok(Signature::P256(signing_key.sign(&msg))),
        }
    }
}
