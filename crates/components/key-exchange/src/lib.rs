//! # The Key Exchange Protocol
//!
//! This crate implements a key exchange protocol with 3 parties, namely server,
//! leader and follower. The goal is to end up with a shared secret (ECDH)
//! between the server and the client. The client in this context is leader and
//! follower combined, which means that each of them will end up with a share of
//! the shared secret. The leader will do all the necessary communication
//! with the server alone and forward all messages from and to the follower.
//!
//! A detailed description of this protocol can be found in our documentation
//! <https://docs.tlsnotary.org/protocol/notarization/key_exchange.html>.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod circuit;
pub(crate) mod error;
mod exchange;
#[cfg(feature = "mock")]
pub mod mock;
pub(crate) mod point_addition;

pub use error::KeyExchangeError;
pub use exchange::MpcKeyExchange;

use async_trait::async_trait;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array,
};
use mpz_vm_core::Vm;
use p256::PublicKey;

/// Pre-master secret.
pub type Pms = Array<U8, 32>;

/// Role in the key exchange protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Leader.
    Leader,
    /// Follower.
    Follower,
}

/// A trait for the 3-party key exchange protocol.
#[async_trait]
pub trait KeyExchange {
    /// Allocate necessary computational resources.
    fn alloc(&mut self, vm: &mut dyn Vm<Binary>) -> Result<Pms, KeyExchangeError>;

    /// Sets the server's public key.
    fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError>;

    /// Gets the server's public key.
    fn server_key(&self) -> Option<PublicKey>;

    /// Computes the client's public key.
    ///
    /// The client's public key in this context is the combined public key (EC
    /// point addition) of the leader's public key and the follower's public
    /// key.
    fn client_key(&self) -> Result<PublicKey, KeyExchangeError>;

    /// Performs one-time setup for the key exchange protocol.
    async fn setup(&mut self, ctx: &mut Context) -> Result<(), KeyExchangeError>;

    /// Computes the shares of the PMS.
    async fn compute_shares(&mut self, ctx: &mut Context) -> Result<(), KeyExchangeError>;

    /// Assigns the PMS shares to the VM.
    fn assign(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), KeyExchangeError>;

    /// Finalizes the key exchange protocol.
    async fn finalize(&mut self) -> Result<(), KeyExchangeError>;
}
