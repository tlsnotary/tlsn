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
mod config;
pub(crate) mod error;
mod exchange;
#[cfg(feature = "mock")]
pub mod mock;
pub(crate) mod point_addition;

pub use config::{
    KeyExchangeConfig, KeyExchangeConfigBuilder, KeyExchangeConfigBuilderError, Role,
};
pub use error::KeyExchangeError;
pub use exchange::MpcKeyExchange;

use async_trait::async_trait;
use mpz_garble::value::ValueRef;
use p256::PublicKey;

/// Pre-master secret.
#[derive(Debug, Clone)]
pub struct Pms(ValueRef);

impl Pms {
    /// Creates a new PMS.
    pub fn new(value: ValueRef) -> Self {
        Self(value)
    }

    /// Gets the value of the PMS.
    pub fn into_value(self) -> ValueRef {
        self.0
    }
}

/// A trait for the 3-party key exchange protocol.
#[async_trait]
pub trait KeyExchange {
    /// Gets the server's public key.
    fn server_key(&self) -> Option<PublicKey>;

    /// Sets the server's public key.
    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError>;

    /// Computes the client's public key.
    ///
    /// The client's public key in this context is the combined public key (EC
    /// point addition) of the leader's public key and the follower's public
    /// key.
    async fn client_key(&mut self) -> Result<PublicKey, KeyExchangeError>;

    /// Performs any necessary one-time setup, returning a reference to the PMS.
    ///
    /// The PMS will not be assigned until `compute_pms` is called.
    async fn setup(&mut self) -> Result<Pms, KeyExchangeError>;

    /// Preprocesses the key exchange.
    async fn preprocess(&mut self) -> Result<(), KeyExchangeError>;

    /// Computes the PMS.
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError>;
}
