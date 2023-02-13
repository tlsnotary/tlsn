#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyExchangeMessage {
    NotaryPublicKey(NotaryPublicKey),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NotaryPublicKey {
    P256(Vec<u8>),
}
