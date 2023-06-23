use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::ContentType;

#[derive(Serialize, Deserialize)]
#[serde(remote = "ContentType")]
pub enum ContentTypeDef {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcTlsMessage {
    HandshakeCommitment(Hash),
    EncryptMessage(EncryptMessage),
    DecryptMessage(DecryptMessage),
    SendCloseNotify(EncryptMessage),
    Close(Close),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Close;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub seq: u64,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub explicit_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub seq: u64,
}
