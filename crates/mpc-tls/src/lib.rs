//! TLSNotary MPC-TLS protocol implementation.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod decode;
mod error;
pub(crate) mod follower;
pub(crate) mod leader;
mod msg;
mod record_layer;
pub(crate) mod utils;

pub use config::{Config, ConfigBuilder, ConfigBuilderError};
pub use error::MpcTlsError;
pub use follower::MpcTlsFollower;
pub use leader::{LeaderCtrl, MpcTlsLeader};

use std::{future::Future, pin::Pin, sync::Arc};

use mpz_memory_core::{
    binary::{Binary, U8},
    Array,
};
use mpz_vm_core::Vm as VmTrait;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::{CipherSuite, ProtocolVersion},
        handshake::Random,
    },
};
use tlsn_common::transcript::TlsTranscript;
use tokio::sync::Mutex;

pub(crate) type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'static>>;
/// Virtual machine type.
pub type Vm = Arc<Mutex<dyn VmTrait<Binary> + Send + Sync + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Leader,
    Follower,
}

/// TLS session keys.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Client write IV.
    pub client_write_iv: Array<U8, 4>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Server write IV.
    pub server_write_iv: Array<U8, 4>,
}

impl From<hmac_sha256::SessionKeys> for SessionKeys {
    fn from(keys: hmac_sha256::SessionKeys) -> Self {
        Self {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
        }
    }
}

/// MPC-TLS Leader output.
#[derive(Debug)]
pub struct LeaderOutput {
    /// TLS protocol version.
    pub protocol_version: ProtocolVersion,
    /// TLS cipher suite.
    pub cipher_suite: CipherSuite,
    /// Server ephemeral public key.
    pub server_key: PublicKey,
    /// Server certificate chain and related details.
    pub server_cert_details: ServerCertDetails,
    /// Key exchange details.
    pub server_kx_details: ServerKxDetails,
    /// Client random
    pub client_random: Random,
    /// Server random
    pub server_random: Random,
    /// TLS transcript.
    pub transcript: TlsTranscript,
    /// TLS session keys.
    pub keys: SessionKeys,
}

/// MPC-TLS Follower output.
#[derive(Debug)]
pub struct FollowerData {
    /// Server ephemeral public key.
    pub server_key: PublicKey,
    /// TLS transcript.
    pub transcript: TlsTranscript,
    /// TLS session keys.
    pub keys: SessionKeys,
}
