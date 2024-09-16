//! Contains message types for communication between leader and follower
use serde::{Deserialize, Serialize};

mod mpc_tls_leader_msg;
pub use mpc_tls_leader_msg::*;

mod mpc_tls_follower_msg;
pub use mpc_tls_follower_msg::*;

/// MPC-TLS protocol message.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ComputeKeyExchange;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ClientFinishedVd;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EncryptClientFinished;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EncryptAlert;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ServerFinishedVd;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct DecryptServerFinished;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct DecryptAlert;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CommitMessage;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EncryptMessage;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct DecryptMessage;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CloseConnection;

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Commit;
