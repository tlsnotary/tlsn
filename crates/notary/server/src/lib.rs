mod auth;
mod cli;
mod config;
mod api;
mod error;
mod middleware;
mod server;
mod server_tracing;
mod service;
mod signing;
#[cfg(feature = "tee_quote")]
mod tee;
mod util;

pub use api::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
pub use cli::CliFields;
pub use config::{
    AuthorizationProperties, LogProperties, NotarizationProperties, NotaryServerProperties, TLSProperties,
};
pub use error::NotaryServerError;
pub use server::{read_pem_file, run_server};
pub use server_tracing::init_tracing;
pub use util::parse_config_file;
