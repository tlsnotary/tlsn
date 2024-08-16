//! This crate provides tooling for instantiating TEE TLS machinery for leader and follower.

//! The main API objects are [TeeTlsLeader] and [TeeTlsFollower], which wrap the necessary
//! cryptographic machinery and also an [TeeTlsChannel] for communication.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
pub(crate) mod error;
pub(crate) mod follower;
pub(crate) mod leader;
pub mod msg;

pub use config::{
    TeeTlsCommonConfig, TeeTlsCommonConfigBuilder, TeeTlsCommonConfigBuilderError,
    TeeTlsFollowerConfig, TeeTlsFollowerConfigBuilder, TeeTlsFollowerConfigBuilderError,
    TeeTlsLeaderConfig, TeeTlsLeaderConfigBuilder, TeeTlsLeaderConfigBuilderError,
    TeeTranscriptConfig, TeeTranscriptConfigBuilder, TeeTranscriptConfigBuilderError,
};
pub use error::TeeTlsError;
pub use follower::{TeeFollowerCtrl, TeeTlsFollower, TeeTlsFollowerData};
pub use leader::{TeeLeaderCtrl, TeeTlsLeader, TeeTlsLeaderData};
use utils_aio::duplex::Duplex;

/// A channel for sending and receiving messages between leader and follower
pub type TeeTlsChannel = Box<dyn Duplex<msg::TeeTlsMessage>>;

/// Sets the role of a party
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeTlsRole {
    Leader,
    Follower,
}
