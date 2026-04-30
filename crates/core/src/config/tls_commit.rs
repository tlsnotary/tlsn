//! TLS commitment configuration.

pub mod mpc;
pub mod proxy;

use crate::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};
use serde::{Deserialize, Serialize};

/// TLS commitment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TlsCommitRequest {
    /// Protocol config for mpc mode.
    Mpc(MpcTlsConfig),
    /// Protocol config for proxy mode.
    Proxy(ProxyTlsConfig),
}

impl From<MpcTlsConfig> for TlsCommitRequest {
    fn from(value: MpcTlsConfig) -> Self {
        Self::Mpc(value)
    }
}

impl From<ProxyTlsConfig> for TlsCommitRequest {
    fn from(value: ProxyTlsConfig) -> Self {
        Self::Proxy(value)
    }
}
