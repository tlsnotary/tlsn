//! This module contains the message types exchanged between user and notary

use p256::PublicKey;

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
    pub notary_key: PublicKey,
}

/// Contains the public key of the server
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerPublicKey {
    pub server_key: PublicKey,
}
