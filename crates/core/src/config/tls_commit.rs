//! TLS commitment configuration.

pub mod mpc;
pub mod proxy;

use serde::{Deserialize, Serialize};

/// Marker type for the MPC-TLS commitment protocol.
#[derive(Debug, Clone, Copy)]
pub struct Mpc;

/// Marker type for the proxy-TLS commitment protocol.
#[derive(Debug, Clone, Copy)]
pub struct Proxy;

/// TLS commitment protocol marker.
pub trait Protocol: sealed::SealedProtocol {}

impl Protocol for Mpc {}
impl Protocol for Proxy {}

/// A TLS commitment protocol configuration.
///
/// Implemented by the concrete configuration types for each supported protocol
/// (e.g. [`mpc::MpcTlsConfig`], [`proxy::ProxyTlsConfig`]). Associates a config
/// with its [`Protocol`] marker.
pub trait CommitConfig:
    Into<TlsCommitProtocolConfig> + Clone + sealed::SealedConfig
{
    /// The protocol marker for this configuration.
    type Protocol: Protocol;
}

impl CommitConfig for mpc::MpcTlsConfig {
    type Protocol = Mpc;
}

impl CommitConfig for proxy::ProxyTlsConfig {
    type Protocol = Proxy;
}

/// TLS commitment protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TlsCommitProtocolConfig {
    /// MPC-TLS configuration.
    Mpc(mpc::MpcTlsConfig),
    /// Proxy-TLS configuration.
    Proxy(proxy::ProxyTlsConfig),
}

impl From<mpc::MpcTlsConfig> for TlsCommitProtocolConfig {
    fn from(config: mpc::MpcTlsConfig) -> Self {
        Self::Mpc(config)
    }
}

impl From<proxy::ProxyTlsConfig> for TlsCommitProtocolConfig {
    fn from(config: proxy::ProxyTlsConfig) -> Self {
        Self::Proxy(config)
    }
}

/// TLS commitment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCommitRequest {
    config: TlsCommitProtocolConfig,
}

impl TlsCommitRequest {
    /// Creates a new request for the given protocol configuration.
    pub fn new(config: TlsCommitProtocolConfig) -> Self {
        Self { config }
    }

    /// Returns the protocol configuration.
    pub fn protocol(&self) -> &TlsCommitProtocolConfig {
        &self.config
    }
}

mod sealed {
    pub trait SealedProtocol {}
    impl SealedProtocol for super::Mpc {}
    impl SealedProtocol for super::Proxy {}

    pub trait SealedConfig {}
    impl SealedConfig for super::mpc::MpcTlsConfig {}
    impl SealedConfig for super::proxy::ProxyTlsConfig {}
}
