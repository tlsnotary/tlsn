mod follower;
mod leader;

pub use leader::{Config, CryptoLeader};

#[derive(Clone, PartialEq)]
pub enum Error {
    /// Encountered when user attempts to run setup again
    AlreadySetup,
}
