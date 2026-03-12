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
pub use leader::MpcTlsLeader;

use std::{future::Future, pin::Pin, sync::Arc};

use mpz_memory_core::binary::Binary;
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
