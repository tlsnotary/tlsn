//! This crate provides tooling for instantiating our MPC machinery for prover and notary.

//! The main API objects are [MpcTlsLeader] and [MpcTlsFollower], which wrap the necessary
//! cryptographic machinery and also an [MpcTlsChannel] for communication.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod follower;
mod leader;
pub mod msg;
pub(crate) mod setup;

pub use config::{
    MpcTlsCommonConfig, MpcTlsCommonConfigBuilder, MpcTlsCommonConfigBuilderError,
    MpcTlsFollowerConfig, MpcTlsFollowerConfigBuilder, MpcTlsFollowerConfigBuilderError,
    MpcTlsLeaderConfig, MpcTlsLeaderConfigBuilder, MpcTlsLeaderConfigBuilderError,
};
pub use error::MpcTlsError;
pub use follower::MpcTlsFollower;
pub use leader::MpcTlsLeader;
pub use setup::setup_components;
use utils_aio::Channel;

/// A channel for sending and receiving messages between notary and prover
pub type MpcTlsChannel = Box<dyn Channel<msg::MpcTlsMessage, Error = std::io::Error>>;

/// Sets the  role of a party
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Leader,
    Follower,
}
