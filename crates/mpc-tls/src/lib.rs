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
    /// Server write MAC key.
    pub server_write_mac_key: Array<U8, 16>,
}
