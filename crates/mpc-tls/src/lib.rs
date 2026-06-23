//! TLSNotary MPC-TLS protocol implementation.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod conn;
mod decode;
mod error;
pub(crate) mod follower;
pub(crate) mod handshake;
pub(crate) mod leader;
mod msg;
mod record_layer;
mod session;
mod vecbuf;

pub use config::{Config, ConfigBuilder, ConfigBuilderError};
pub use conn::IoState;
pub use error::MpcTlsError;
pub use follower::MpcTlsFollower;
pub use leader::MpcTlsLeader;

// TLS-client policy types. The handshake module is internal; these are the
// public surface for configuring the client and verifying the server.
pub use handshake::{
    Certificate, ClientConfig, Error as TlsError, PrivateKey, ResolvesClientCert, RootCertStore,
    ServerName, sign,
};

use std::sync::Arc;

use mpz_memory_core::{
    Array,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm as VmTrait;

use tokio::sync::Mutex;

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
    /// Server write MAC key.
    pub server_write_mac_key: Array<U8, 16>,
}
