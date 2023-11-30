//! Contains message types for communication between leader and follower

use enum_try_as_inner::EnumTryAsInner;
use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use tls_core::msgs::{
    enums::{ContentType, ProtocolVersion},
    message::OpaqueMessage,
};

/// MPC protocol level message types
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize, EnumTryAsInner)]
#[derive_err(Debug)]
pub enum MpcTlsMessage {
    HandshakeCommitment(Hash),
    EncryptMessage(EncryptMessage),
    CommitMessage(OpaqueMessage),
    DecryptMessage,
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
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub len: usize,
}
