mod master;
mod slave;

pub use master::{Config, CryptoMaster};

#[derive(Clone, PartialEq)]
pub enum Error {
    /// Encountered when user attempts to run setup again
    AlreadySetup,
}
