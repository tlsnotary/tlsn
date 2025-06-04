pub mod bench;
pub mod network;
pub mod rpc;
pub mod test;

use serde::{Deserialize, Serialize};

use crate::network::NetworkConfig;

pub const TEST_PROTO_BANDWIDTH: usize = 1000;
pub const TEST_PROTO_DELAY: usize = 10;
pub const TEST_APP_BANDWIDTH: usize = 1000;
pub const TEST_APP_DELAY: usize = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Role {
    Prover,
    Verifier,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Id {
    Zero,
    One,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IoMode {
    Client,
    Server,
}

impl TryFrom<&str> for IoMode {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "client" => Ok(IoMode::Client),
            "server" => Ok(IoMode::Server),
            _ => Err("Invalid io mode"),
        }
    }
}

impl ToString for IoMode {
    fn to_string(&self) -> String {
        match self {
            IoMode::Client => "client".to_string(),
            IoMode::Server => "server".to_string(),
        }
    }
}

#[derive(Debug, Clone, bon::Builder, Serialize, Deserialize)]
pub struct ExecutorConfig {
    id: Id,
    io_mode: IoMode,
    network_config: NetworkConfig,
}

impl ExecutorConfig {
    /// Returns the id.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Returns the io mode.
    pub fn io_mode(&self) -> &IoMode {
        &self.io_mode
    }

    /// Returns the network config.
    pub fn network(&self) -> &NetworkConfig {
        &self.network_config
    }
}
