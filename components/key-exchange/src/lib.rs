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
pub type KeyExchangeChannel = Box<dyn Duplex<KeyExchangeMessage>>;

use async_trait::async_trait;
use mpz_garble::value::ValueRef;
use p256::{PublicKey, SecretKey};
use utils_aio::duplex::Duplex;

/// Pre-master secret.
#[derive(Debug, Clone)]
pub struct Pms(ValueRef);

impl Pms {
    /// Create a new PMS
    pub fn new(value: ValueRef) -> Self {
        Self(value)
    }

    /// Get the value of the PMS
    pub fn into_value(self) -> ValueRef {
        self.0
    }
}

/// An error that can occur during the key exchange protocol
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KeyExchangeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MemoryError(#[from] mpz_garble::MemoryError),
    #[error(transparent)]
    LoadError(#[from] mpz_garble::LoadError),
    #[error(transparent)]
    ExecutionError(#[from] mpz_garble::ExecutionError),
    #[error(transparent)]
    DecodeError(#[from] mpz_garble::DecodeError),
    #[error(transparent)]
    PointAdditionError(#[from] point_addition::PointAdditionError),
    #[error(transparent)]
    PublicKey(#[from] p256::elliptic_curve::Error),
    #[error(transparent)]
    KeyParseError(#[from] msg::KeyParseError),
    #[error("Server Key not set")]
    NoServerKey,
    #[error("Private key not set")]
    NoPrivateKey,
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("PMS equality check failed")]
    CheckFailed,
}

/// A trait for the 3-party key exchange protocol
#[async_trait]
pub trait KeyExchange {
    /// Get the server's public key
    fn server_key(&self) -> Option<PublicKey>;

    /// Set the server's public key
    fn set_server_key(&mut self, server_key: PublicKey);

    /// Performs any necessary one-time setup, returning a reference to the PMS.
    ///
    /// The PMS will not be assigned until `compute_pms` is called.
    async fn setup(&mut self) -> Result<Pms, KeyExchangeError>;

    /// Compute the client's public key
    ///
    /// The client's public key in this context is the combined public key (EC point addition) of
    /// the leader's public key and the follower's public key.
    async fn compute_client_key(
        &mut self,
        private_key: SecretKey,
    ) -> Result<Option<PublicKey>, KeyExchangeError>;

    /// Computes the PMS
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError>;
}
