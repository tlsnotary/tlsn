//! # The Key Exchange Protocol
//!
//! This crate implements a key exchange protocol with 3 parties, namely server, leader and
//! follower. The goal is to end up with a shared secret (ECDH) between the server and the client.
//! The client in this context is leader and follower combined, which means that each of them will
//! end up with a share of the shared secret. The leader will do all the necessary communication
//! with the server alone and forward all messages from and to the follower.
//!
//! A detailed description of this protocol can be found in our documentation
//! <https://docs.tlsnotary.org/protocol/notarization/key_exchange.html>.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod circuit;
mod config;
mod exchange;
#[cfg(feature = "mock")]
pub mod mock;
pub mod msg;

pub use config::{
    KeyExchangeConfig, KeyExchangeConfigBuilder, KeyExchangeConfigBuilderError, Role,
};
pub use exchange::KeyExchangeCore;
pub use msg::KeyExchangeMessage;

/// A channel for exchanging key exchange messages
pub type KeyExchangeChannel = Box<dyn Channel<KeyExchangeMessage, Error = std::io::Error> + Send>;

use async_trait::async_trait;
use mpc_garble::ValueRef;
use p256::{PublicKey, SecretKey};
use utils_aio::Channel;

/// Pre-master secret.
#[derive(Debug, Clone)]
pub struct Pms(ValueRef);

impl Pms {
    /// Create a new PMS
    pub fn new(value: ValueRef) -> Self {
        Self(value)
    }

    /// Get the value of the PMS
    pub fn value(&self) -> &ValueRef {
        &self.0
    }
}

/// An error that can occur during the key exchange protocol
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KeyExchangeError {
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MemoryError(#[from] mpc_garble::MemoryError),
    #[error(transparent)]
    ExecutionError(#[from] mpc_garble::ExecutionError),
    #[error(transparent)]
    DecodeError(#[from] mpc_garble::DecodeError),
    #[error("Unable to compute public key: {0}")]
    PublicKey(#[from] p256::elliptic_curve::Error),
    #[error(transparent)]
    KeyParseError(#[from] msg::KeyParseError),
    #[error("Server Key not set")]
    NoServerKey,
    #[error("Private key not set")]
    NoPrivateKey,
    #[error("PMSShares are not set")]
    NoPMSShares,
    #[error("PMS equality check failed")]
    CheckFailed,
    #[error("UnexpectedMessage: {0:?}")]
    Unexpected(KeyExchangeMessage),
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] point_addition::PointAdditionError),
}

/// A trait for computing PMS shares
#[async_trait]
pub trait ComputePms {
    /// Computes the PMS
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError>;
}

/// A trait for the leader of the key exchange protocol
#[async_trait]
pub trait KeyExchangeLead: ComputePms {
    /// Compute the client's public key
    ///
    /// The client's public key in this context is the combined public key (EC point addition) of
    /// the leader's public key and the follower's public key.
    async fn compute_client_key(
        &mut self,
        leader_private_key: SecretKey,
    ) -> Result<PublicKey, KeyExchangeError>;

    /// Set the server's public key
    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError>;
}

/// A trait for the follower of the key exchange protocol
#[async_trait]
pub trait KeyExchangeFollow: ComputePms {
    /// Send the follower's public key to the key exchange leader
    async fn send_public_key(
        &mut self,
        follower_private_key: SecretKey,
    ) -> Result<(), KeyExchangeError>;

    /// Receive the server's public key from the key exchange leader
    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError>;
}
