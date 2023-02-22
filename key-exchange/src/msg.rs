//! This module contains the message types exchanged between user and notary

use super::KeyExchangeError;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};

/// A type for messages exchanged between user and notary during the key exchange protocol
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyExchangeMessage {
    NotaryPublicKey(NotaryPublicKey),
    ServerPublicKey(ServerPublicKey),
}

/// Contains the public key of the notary
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NotaryPublicKey {
    pub notary_key: Vec<u8>,
}

/// Contains the public key of the server
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerPublicKey {
    pub server_key: Vec<u8>,
}

impl From<PublicKey> for NotaryPublicKey {
    fn from(value: PublicKey) -> Self {
        let notary_key = value.to_encoded_point(false).as_bytes().to_vec();
        NotaryPublicKey { notary_key }
    }
}

impl TryFrom<NotaryPublicKey> for PublicKey {
    type Error = KeyExchangeError;

    fn try_from(value: NotaryPublicKey) -> Result<Self, Self::Error> {
        PublicKey::from_sec1_bytes(&value.notary_key).map_err(Into::into)
    }
}

impl From<PublicKey> for ServerPublicKey {
    fn from(value: PublicKey) -> Self {
        let server_key = value.to_encoded_point(false).as_bytes().to_vec();
        ServerPublicKey { server_key }
    }
}

impl TryFrom<ServerPublicKey> for PublicKey {
    type Error = KeyExchangeError;

    fn try_from(value: ServerPublicKey) -> Result<Self, Self::Error> {
        PublicKey::from_sec1_bytes(&value.server_key).map_err(Into::into)
    }
}
