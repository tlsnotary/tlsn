//! This module contains the message types exchanged between the prover and the TLS verifier.

use std::fmt::{self, Display, Formatter};

use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};
use serde::{Deserialize, Serialize};

/// A type for messages exchanged between the prover and the TLS verifier during the key exchange
/// protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum KeyExchangeMessage {
    FollowerPublicKey(PublicKey),
    ServerPublicKey(PublicKey),
}

/// A wrapper for a serialized public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// The sec1 serialized public key.
    pub key: Vec<u8>,
}

/// An error that can occur during parsing of a public key.
#[derive(Debug, thiserror::Error)]
pub struct KeyParseError(#[from] p256::elliptic_curve::Error);

impl Display for KeyParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to parse public key: {}", self.0)
    }
}

impl From<P256PublicKey> for PublicKey {
    fn from(value: P256PublicKey) -> Self {
        let key = value.to_encoded_point(false).as_bytes().to_vec();
        PublicKey { key }
    }
}

impl TryFrom<PublicKey> for P256PublicKey {
    type Error = KeyParseError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        P256PublicKey::from_sec1_bytes(&value.key).map_err(Into::into)
    }
}
