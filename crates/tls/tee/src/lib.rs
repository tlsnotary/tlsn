//! This crate provides tooling for instantiating MPC TLS machinery for leader and follower.

//! The main API objects are [MpcTlsLeader] and [MpcTlsFollower], which wrap the necessary
//! cryptographic machinery and also an [MpcTlsChannel] for communication.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
pub(crate) mod error;
pub(crate) mod follower;
pub(crate) mod leader;
pub mod msg;
pub(crate) mod record_layer;

pub use config::{
    TeeTlsCommonConfig, TeeTlsCommonConfigBuilder, TeeTlsCommonConfigBuilderError,
    TeeTlsFollowerConfig, TeeTlsFollowerConfigBuilder, TeeTlsFollowerConfigBuilderError,
    TeeTlsLeaderConfig, TeeTlsLeaderConfigBuilder, TeeTlsLeaderConfigBuilderError,
    TeeTranscriptConfig, TeeTranscriptConfigBuilder, TeeTranscriptConfigBuilderError,
};
pub use error::TeeTlsError;
pub use follower::{TeeFollowerCtrl, TeeTlsFollower};
pub use leader::{TeeLeaderCtrl, TeeTlsLeader};
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