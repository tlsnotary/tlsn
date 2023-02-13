use p256::PublicKey;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyExchangeMessage {
    NotaryPublicKey(NotaryPublicKey),
    ServerPublicKey(ServerPublicKey),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NotaryPublicKey {
    pub notary_key: PublicKey,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerPublicKey {
    pub server_key: PublicKey,
}
