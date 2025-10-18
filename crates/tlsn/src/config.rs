//! TLSNotary protocol config and config utilities.

use once_cell::sync::Lazy;
use semver::Version;
use serde::{Deserialize, Serialize};

pub use tlsn_core::webpki::{CertificateDer, PrivateKeyDer, RootCertStore};

// Default is 32 bytes to decrypt the TLS protocol messages.
const DEFAULT_MAX_RECV_ONLINE: usize = 32;

// Current version that is running.
pub(crate) static VERSION: Lazy<Version> = Lazy::new(|| {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("cargo pkg version should be a valid semver")
});

/// Protocol configuration to be set up initially by prover and verifier.
#[derive(derive_builder::Builder, Clone, Debug, Deserialize, Serialize)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct ProtocolConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: usize,
    /// Maximum number of application data records that can be sent.
    #[builder(setter(strip_option), default)]
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be decrypted online, i.e. while the
    /// MPC-TLS connection is active.
    #[builder(default = "DEFAULT_MAX_RECV_ONLINE")]
    max_recv_data_online: usize,
    /// Maximum number of bytes that can be received.
    max_recv_data: usize,
    /// Maximum number of received application data records that can be
    /// decrypted online, i.e. while the MPC-TLS connection is active.
    #[builder(setter(strip_option), default)]
    max_recv_records_online: Option<usize>,
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the MPC-TLS connection.
    #[builder(default = "true")]
    defer_decryption_from_start: bool,
    /// Network settings.
    #[builder(default)]
    network: NetworkSetting,
}

impl ProtocolConfigBuilder {
    fn validate(&self) -> Result<(), String> {
        if self.max_recv_data_online > self.max_recv_data {
            return Err(
                "max_recv_data_online must be smaller or equal to max_recv_data".to_string(),
            );
        }
        Ok(())
    }
}

impl ProtocolConfig {
    /// Creates a new builder for `ProtocolConfig`.
    pub fn builder() -> ProtocolConfigBuilder {
        ProtocolConfigBuilder::default()
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of application data records that can
    /// be sent.
    pub fn max_sent_records(&self) -> Option<usize> {
        self.max_sent_records
    }

    /// Returns the maximum number of bytes that can be decrypted online.
    pub fn max_recv_data_online(&self) -> usize {
        self.max_recv_data_online
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Returns the maximum number of received application data records that
    /// can be decrypted online.
    pub fn max_recv_records_online(&self) -> Option<usize> {
        self.max_recv_records_online
    }

    /// Returns whether the `deferred decryption` feature is toggled on from the
    /// start of the MPC-TLS connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    /// Returns the network settings.
    pub fn network(&self) -> NetworkSetting {
        self.network
    }
}

/// Settings for the network environment.
///
/// Provides optimization options to adapt the protocol to different network
/// situations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkSetting {
    /// Reduces network round-trips at the expense of consuming more network
    /// bandwidth.
    Bandwidth,
    /// Reduces network bandwidth utilization at the expense of more network
    /// round-trips.
    Latency,
}

impl Default for NetworkSetting {
    fn default() -> Self {
        Self::Latency
    }
}
