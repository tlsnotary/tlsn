// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
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

pub type MpcTlsChannel = Box<dyn Channel<msg::MpcTlsMessage, Error = std::io::Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Leader,
    Follower,
}
