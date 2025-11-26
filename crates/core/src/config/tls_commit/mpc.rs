//! MPC-TLS commitment protocol configuration.

use serde::{Deserialize, Serialize};

// Default is 32 bytes to decrypt the TLS protocol messages.
const DEFAULT_MAX_RECV_ONLINE: usize = 32;

/// MPC-TLS commitment protocol configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "unchecked::MpcTlsConfigUnchecked")]
pub struct MpcTlsConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: usize,
    /// Maximum number of application data records that can be sent.
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be decrypted online, i.e. while the
    /// MPC-TLS connection is active.
    max_recv_data_online: usize,
    /// Maximum number of bytes that can be received.
    max_recv_data: usize,
    /// Maximum number of received application data records that can be
    /// decrypted online, i.e. while the MPC-TLS connection is active.
    max_recv_records_online: Option<usize>,
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the MPC-TLS connection.
    defer_decryption_from_start: bool,
    /// Network settings.
    network: NetworkSetting,
}

impl MpcTlsConfig {
    /// Creates a new builder.
    pub fn builder() -> MpcTlsConfigBuilder {
        MpcTlsConfigBuilder::default()
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

fn validate(config: MpcTlsConfig) -> Result<MpcTlsConfig, MpcTlsConfigError> {
    if config.max_recv_data_online > config.max_recv_data {
        return Err(ErrorRepr::InvalidValue {
            name: "max_recv_data_online",
            reason: format!(
                "must be <= max_recv_data ({} > {})",
                config.max_recv_data_online, config.max_recv_data
            ),
        }
        .into());
    }

    Ok(config)
}

/// Builder for [`MpcTlsConfig`].
#[derive(Debug, Default)]
pub struct MpcTlsConfigBuilder {
    max_sent_data: Option<usize>,
    max_sent_records: Option<usize>,
    max_recv_data_online: Option<usize>,
    max_recv_data: Option<usize>,
    max_recv_records_online: Option<usize>,
    defer_decryption_from_start: Option<bool>,
    network: Option<NetworkSetting>,
}

impl MpcTlsConfigBuilder {
    /// Sets the maximum number of bytes that can be sent.
    pub fn max_sent_data(mut self, max_sent_data: usize) -> Self {
        self.max_sent_data = Some(max_sent_data);
        self
    }

    /// Sets the maximum number of application data records that can be sent.
    pub fn max_sent_records(mut self, max_sent_records: usize) -> Self {
        self.max_sent_records = Some(max_sent_records);
        self
    }

    /// Sets the maximum number of bytes that can be decrypted online.
    pub fn max_recv_data_online(mut self, max_recv_data_online: usize) -> Self {
        self.max_recv_data_online = Some(max_recv_data_online);
        self
    }

    /// Sets the maximum number of bytes that can be received.
    pub fn max_recv_data(mut self, max_recv_data: usize) -> Self {
        self.max_recv_data = Some(max_recv_data);
        self
    }

    /// Sets the maximum number of received application data records that can
    /// be decrypted online.
    pub fn max_recv_records_online(mut self, max_recv_records_online: usize) -> Self {
        self.max_recv_records_online = Some(max_recv_records_online);
        self
    }

    /// Sets whether the `deferred decryption` feature is toggled on from the
    /// start of the MPC-TLS connection.
    pub fn defer_decryption_from_start(mut self, defer_decryption_from_start: bool) -> Self {
        self.defer_decryption_from_start = Some(defer_decryption_from_start);
        self
    }

    /// Sets the network settings.
    pub fn network(mut self, network: NetworkSetting) -> Self {
        self.network = Some(network);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<MpcTlsConfig, MpcTlsConfigError> {
        let Self {
            max_sent_data,
            max_sent_records,
            max_recv_data_online,
            max_recv_data,
            max_recv_records_online,
            defer_decryption_from_start,
            network,
        } = self;

        let max_sent_data = max_sent_data.ok_or(ErrorRepr::MissingField {
            name: "max_sent_data",
        })?;

        let max_recv_data_online = max_recv_data_online.unwrap_or(DEFAULT_MAX_RECV_ONLINE);
        let max_recv_data = max_recv_data.ok_or(ErrorRepr::MissingField {
            name: "max_recv_data",
        })?;

        let defer_decryption_from_start = defer_decryption_from_start.unwrap_or(true);
        let network = network.unwrap_or_default();

        validate(MpcTlsConfig {
            max_sent_data,
            max_sent_records,
            max_recv_data_online,
            max_recv_data,
            max_recv_records_online,
            defer_decryption_from_start,
            network,
        })
    }
}

/// Settings for the network environment.
///
/// Provides optimization options to adapt the protocol to different network
/// situations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum NetworkSetting {
    /// Reduces network round-trips at the expense of consuming more network
    /// bandwidth.
    Bandwidth,
    /// Reduces network bandwidth utilization at the expense of more network
    /// round-trips.
    #[default]
    Latency,
}

/// Error for [`MpcTlsConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MpcTlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
    #[error("invalid value for field({name}): {reason}")]
    InvalidValue { name: &'static str, reason: String },
}

mod unchecked {
    use super::*;

    #[derive(Deserialize)]
    pub(super) struct MpcTlsConfigUnchecked {
        max_sent_data: usize,
        max_sent_records: Option<usize>,
        max_recv_data_online: usize,
        max_recv_data: usize,
        max_recv_records_online: Option<usize>,
        defer_decryption_from_start: bool,
        network: NetworkSetting,
    }

    impl TryFrom<MpcTlsConfigUnchecked> for MpcTlsConfig {
        type Error = MpcTlsConfigError;

        fn try_from(value: MpcTlsConfigUnchecked) -> Result<Self, Self::Error> {
            validate(MpcTlsConfig {
                max_sent_data: value.max_sent_data,
                max_sent_records: value.max_sent_records,
                max_recv_data_online: value.max_recv_data_online,
                max_recv_data: value.max_recv_data,
                max_recv_records_online: value.max_recv_records_online,
                defer_decryption_from_start: value.defer_decryption_from_start,
                network: value.network,
            })
        }
    }
}
