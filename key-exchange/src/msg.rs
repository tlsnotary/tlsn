//! This module contains the message types exchanged between user and notary

use super::KeyExchangeError;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};

/// A type for messages exchanged between user and notary during the key exchange protocol
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyExchangeMessage {
    NotaryPublicKey(PublicKey),
    ServerPublicKey(PublicKey),
}

/// A wrapper for a serialized public key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    pub key: Vec<u8>,
}

impl From<P256PublicKey> for PublicKey {
    fn from(value: P256PublicKey) -> Self {
        let key = value.to_encoded_point(false).as_bytes().to_vec();
        PublicKey { key }
    }
}

impl TryFrom<PublicKey> for P256PublicKey {
    type Error = KeyExchangeError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        P256PublicKey::from_sec1_bytes(&value.key).map_err(Into::into)
    }
}
