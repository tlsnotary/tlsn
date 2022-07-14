mod follower;
mod leader;

pub use leader::{Config, CryptoLeader};

use mpc_aio::point_addition::PointAdditionError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("encountered error during point addition: {0}")]
    PointAdditionError(#[from] PointAdditionError),
    #[error("")]
    AlreadySetup,
}
