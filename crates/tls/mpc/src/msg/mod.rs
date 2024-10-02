//! Contains message types for communication between leader and follower and actor messages.

use serde::{Deserialize, Serialize};

pub mod mpc_tls_follower_msg;
pub mod mpc_tls_leader_msg;

/// MPC-TLS protocol message.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcTlsMessage {
    ComputeKeyExchange(ComputeKeyExchange),
    ClientFinishedVd(ClientFinishedVd),
    EncryptClientFinished(EncryptClientFinished),
    EncryptAlert(EncryptAlert),
    ServerFinishedVd(ServerFinishedVd),
    DecryptServerFinished(DecryptServerFinished),
    DecryptAlert(DecryptAlert),
    /// A leader commitment to a TLS message received from the server.
    CommitMessage(CommitMessage),
    EncryptMessage(EncryptMessage),
    DecryptMessage(DecryptMessage),
    CloseConnection(CloseConnection),
    Commit(Commit),
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeKeyExchange {
    pub server_random: [u8; 32],
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptClientFinished;

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptAlert {
    pub msg: Vec<u8>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptServerFinished {
    pub ciphertext: Vec<u8>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptAlert {
    pub ciphertext: Vec<u8>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMessage {
    pub msg: Vec<u8>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMessage {
    pub len: usize,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptMessage;

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseConnection;

#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit;
