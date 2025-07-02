use serde::{Deserialize, Serialize};
use tls_core::{
    key::PublicKey,
    msgs::enums::{ContentType, ProtocolVersion},
};

use crate::record_layer::{DecryptMode, EncryptMode};

/// MPC-TLS protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    SetClientRandom(SetClientRandom),
    StartHandshake(StartHandshake),
    SetServerRandom(SetServerRandom),
    SetServerKey(SetServerKey),
    ClientFinishedVd(ClientFinishedVd),
    ServerFinishedVd(ServerFinishedVd),
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    StartTraffic,
    Flush { is_decrypting: bool },
    CloseConnection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetClientRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StartHandshake {
    pub(crate) time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerKey {
    pub(crate) key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Decrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) mode: DecryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Encrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) mode: EncryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ClientFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CloseConnection;
