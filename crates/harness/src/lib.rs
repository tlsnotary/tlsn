pub mod bench;
#[cfg(feature = "runner")]
pub mod cli;
pub(crate) mod config;
pub mod io;
mod provider;
#[cfg(feature = "runner")]
pub mod runner;
pub(crate) mod spawn;
pub mod test;
mod tests;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use provider::{ProverProvider, VerifierProvider};
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "runner", derive(clap::ValueEnum))]
pub enum Target {
    Native,
    Browser,
}

impl Default for Target {
    fn default() -> Self {
        Self::Native
    }
}

pub static DEFAULT_SERVER_IP: &str = "127.0.0.1";
pub static DEFAULT_WASM_PORT: u16 = 8013;
pub static DEFAULT_WS_PORT: u16 = 8080;
pub static DEFAULT_SERVER_PORT: u16 = 8083;
pub static DEFAULT_VERIFIER_PORT: u16 = 8010;
pub static DEFAULT_NOTARY_PORT: u16 = 8011;
pub static DEFAULT_PROVER_PORT: u16 = 8012;
