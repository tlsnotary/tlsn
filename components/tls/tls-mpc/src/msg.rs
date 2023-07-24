//! Contains message types for communication between leader and follower

use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::ContentType;

/// An enum for different record types on the TLS level
#[allow(missing_docs)]
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

/// An enum for different message types on the MPC protocol level
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcTlsMessage {
    HandshakeCommitment(Hash),
    EncryptMessage(EncryptMessage),
    DecryptMessage(DecryptMessage),
    SendCloseNotify(EncryptMessage),
    Close(Close),
}

/// Close the connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Close;

/// Encrypt a message
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub seq: u64,
    pub len: usize,
}

/// Decrypt a message
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub explicit_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub seq: u64,
}
