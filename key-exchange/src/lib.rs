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

mod circuit;
mod config;
mod exchange;
#[cfg(feature = "mock")]
pub mod mock;
pub mod msg;
mod role;

use async_trait::async_trait;
use mpc_garble::{factory::GCFactoryError, GCError};
use mpc_circuits::{CircuitError, GroupError};
use mpc_garble_core::{
    exec::dual::DualExConfigBuilderError, ActiveLabels, EncodingError, Error, FullLabels,
};
pub use msg::KeyExchangeMessage;
use p256::{PublicKey, SecretKey};
use utils_aio::Channel;

pub use exchange::KeyExchangeCore;

/// A channel for exchanging key exchange messages
pub type KeyExchangeChannel = Box<dyn Channel<KeyExchangeMessage, Error = std::io::Error> + Send>;

/// An error that can occur during the key exchange protocol
#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("Unable to compute public key: {0}")]
    PublicKey(#[from] p256::elliptic_curve::Error),
    #[error("Server Key not set")]
    NoServerKey,
    #[error("Private key not set")]
    NoPrivateKey,
    #[error("PMSShares are not set")]
    NoPMSShares,
    #[error("Encoder is not set")]
    NoEncoder,
    #[error("PMS equality check failed")]
    CheckFailed,
    #[error("Encoding Error: {0}")]
    Encoding(#[from] EncodingError),
    #[error("Circuit Error: {0}")]
    Circuit(#[from] CircuitError),
    #[error("Group Error: {0}")]
    Group(#[from] GroupError),
    #[error("Garbled Circuit Error: {0}")]
    GCError(#[from] GCError),
    #[error("DualExConigBuilder Error: {0}")]
    DualExConfig(#[from] DualExConfigBuilderError),
    #[error("Error during decoding of output: {0}")]
    Decoding(#[from] Error),
    #[error("GC Factory Error: {0}")]
    GCFactoryError(#[from] GCFactoryError),
    #[error("IOError: {0}")]
    IOError(#[from] std::io::Error),
    #[error("UnexpectedMessage: {0:?}")]
    Unexpected(KeyExchangeMessage),
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] point_addition::PointAdditionError),
}

/// A trait for the leader of the key exchange protocol
#[async_trait]
pub trait KeyExchangeLead {
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

    /// Compute PMS shares
    ///
    /// PMS shares are an additive sharing of the x-coordinate of the curve point resulting from an
    /// ECDH handshake between server and client
    async fn compute_pms_shares(&mut self) -> Result<(), KeyExchangeError>;

    /// Compute PMS labels
    ///
    /// The returned labels are used as cached inputs for another circuit
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError>;
}

/// A trait for the follower of the key exchange protocol
#[async_trait]
pub trait KeyExchangeFollow {
    /// Send the follower's public key to the key exchange leader
    async fn send_public_key(
        &mut self,
        follower_private_key: SecretKey,
    ) -> Result<(), KeyExchangeError>;

    /// Receive the server's public key from the key exchange leader
    async fn receive_server_key(&mut self) -> Result<(), KeyExchangeError>;

    /// Compute PMS shares
    ///
    /// PMS shares are an additive sharing of the x-coordinate of the curve point resulting from an
    /// ECDH handshake between server and client
    async fn compute_pms_shares(&mut self) -> Result<(), KeyExchangeError>;

    /// Compute PMS labels
    ///
    /// The returned labels are used as cached inputs for another circuit
    async fn compute_pms_labels(&mut self) -> Result<PMSLabels, KeyExchangeError>;
}

/// A wrapper struct for the PMS labels
///
/// PMS labels are encrypted circuit inputs for computing the master secrets
#[derive(Debug, Clone)]
pub struct PMSLabels {
    pub active_labels: ActiveLabels,
    pub full_labels: FullLabels,
}
