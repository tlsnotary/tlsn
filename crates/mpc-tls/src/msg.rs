use serde::{Deserialize, Serialize};
use tls_core::{
    key::PublicKey,
    msgs::enums::{ContentType, ProtocolVersion},
};

/// MPC-TLS protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    /// The client random of the TLS connection.
    SetClientRandom([u8; 32]),
    /// The server parameters of the TLS handshake.
    ServerHello(ServerHello),
    /// The handshake hash for computing the client Finished verify data.
    ClientFinishedVd([u8; 32]),
    /// The handshake hash for computing the server Finished verify data.
    ServerFinishedVd([u8; 32]),
    /// An outgoing record to encrypt.
    Encrypt(Encrypt),
    /// An incoming record to decrypt.
    Decrypt(Decrypt),
    /// Starts processing of application data.
    StartTraffic,
    /// Flushes the record layer.
    Flush {
        /// Whether application data is decrypted while the connection is
        /// active.
        is_decrypting: bool,
    },
    /// Closes the connection.
    CloseConnection,
}

/// Server parameters of the TLS handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerHello {
    /// The time of the handshake as unix timestamp in seconds.
    pub(crate) time: u64,
    /// The server random.
    pub(crate) random: [u8; 32],
    /// The server ephemeral public key.
    pub(crate) key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Decrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Encrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    /// The plaintext of the record, if it is public.
    pub(crate) plaintext: Option<Vec<u8>>,
}
