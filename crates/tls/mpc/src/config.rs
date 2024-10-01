use derive_builder::Builder;

static DEFAULT_OPAQUE_TX_TRANSCRIPT_ID: &str = "opaque_tx";
static DEFAULT_OPAQUE_RX_TRANSCRIPT_ID: &str = "opaque_rx";
static DEFAULT_TX_TRANSCRIPT_ID: &str = "tx";
static DEFAULT_RX_TRANSCRIPT_ID: &str = "rx";
const DEFAULT_TRANSCRIPT_MAX_SIZE: usize = 1 << 14;

/// Transcript configuration.
#[derive(Debug, Clone, Builder)]
pub struct TranscriptConfig {
    /// The transcript id.
    id: String,
    /// The "opaque" transcript id, used for parts of the transcript that are
    /// not part of the application data.
    opaque_id: String,
    /// The maximum number of bytes that can be written to the transcript during
    /// the **online** phase, i.e. while the MPC-TLS connection is active.
    max_online_size: usize,
    /// The maximum number of bytes that can be written to the transcript during
    /// the **offline** phase, i.e. after the MPC-TLS connection was closed.
    max_offline_size: usize,
}

impl TranscriptConfig {
    /// Creates a new default builder for the sent transcript config.
    pub fn default_tx() -> TranscriptConfigBuilder {
        let mut builder = TranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_TX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_TX_TRANSCRIPT_ID.to_string())
            .max_online_size(DEFAULT_TRANSCRIPT_MAX_SIZE)
            .max_offline_size(0);

        builder
    }

    /// Creates a new default builder for the received transcript config.
    pub fn default_rx() -> TranscriptConfigBuilder {
        let mut builder = TranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_RX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_RX_TRANSCRIPT_ID.to_string())
            .max_online_size(0)
            .max_offline_size(DEFAULT_TRANSCRIPT_MAX_SIZE);

        builder
    }

    /// Creates a new builder for `TranscriptConfig`.
    pub fn builder() -> TranscriptConfigBuilder {
        TranscriptConfigBuilder::default()
    }

    /// Returns the transcript id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the "opaque" transcript id.
    pub fn opaque_id(&self) -> &str {
        &self.opaque_id
    }

    /// Returns the maximum number of bytes that can be written to the
    /// transcript during the **online** phase, i.e. while the MPC-TLS
    /// connection is active.
    pub fn max_online_size(&self) -> usize {
        self.max_online_size
    }

    /// Returns the maximum number of bytes that can be written to the
    /// transcript during the **offline** phase, i.e. after the MPC-TLS
    /// connection was closed.
    pub fn max_offline_size(&self) -> usize {
        self.max_offline_size
    }
}

/// Configuration options which are common to both the leader and the follower
#[derive(Debug, Clone, Builder)]
pub struct MpcTlsCommonConfig {
    /// The number of threads to use
    #[builder(default = "8")]
    num_threads: usize,
    /// The sent data transcript configuration.
    #[builder(default = "TranscriptConfig::default_tx().build().unwrap()")]
    tx_config: TranscriptConfig,
    /// The received data transcript configuration.
    #[builder(default = "TranscriptConfig::default_rx().build().unwrap()")]
    rx_config: TranscriptConfig,
    /// Whether the leader commits to the handshake data.
    #[builder(default = "true")]
    handshake_commit: bool,
}

impl MpcTlsCommonConfig {
    /// Creates a new builder for `MpcTlsCommonConfig`.
    pub fn builder() -> MpcTlsCommonConfigBuilder {
        MpcTlsCommonConfigBuilder::default()
    }

    /// Returns the number of threads to use.
    pub fn num_threads(&self) -> usize {
        self.num_threads
    }

    /// Returns the configuration for the sent data transcript.
    pub fn tx_config(&self) -> &TranscriptConfig {
        &self.tx_config
    }

    /// Returns the configuration for the received data transcript.
    pub fn rx_config(&self) -> &TranscriptConfig {
        &self.rx_config
    }

    /// Whether the leader commits to the handshake data.
    pub fn handshake_commit(&self) -> bool {
        self.handshake_commit
    }
}

/// Configuration for the leader
#[allow(missing_docs)]
#[derive(Debug, Clone, Builder)]
pub struct MpcTlsLeaderConfig {
    common: MpcTlsCommonConfig,
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the MPC-TLS connection.
    ///
    /// The received data will be decrypted locally without MPC, thus improving
    /// bandwidth usage and performance.
    ///
    /// Decryption of the data received while `deferred decryption` is toggled
    /// on will be deferred until after the MPC-TLS connection is closed.
    /// If you need to decrypt some subset of data received from the TLS peer
    /// while the MPC-TLS connection is active, you must toggle `deferred
    /// decryption` **off** for that subset of data.
    #[builder(default = "true")]
    defer_decryption_from_start: bool,
}

impl MpcTlsLeaderConfig {
    /// Creates a new builder for `MpcTlsLeaderConfig`.
    pub fn builder() -> MpcTlsLeaderConfigBuilder {
        MpcTlsLeaderConfigBuilder::default()
    }

    /// Returns the common config.
    pub fn common(&self) -> &MpcTlsCommonConfig {
        &self.common
    }

    /// Returns whether the `deferred decryption` feature is toggled on from the
    /// start of the MPC-TLS connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }
}

/// Configuration for the follower
#[allow(missing_docs)]
#[derive(Debug, Clone, Builder)]
pub struct MpcTlsFollowerConfig {
    common: MpcTlsCommonConfig,
}

impl MpcTlsFollowerConfig {
    /// Creates a new builder for `MpcTlsFollowerConfig`.
    pub fn builder() -> MpcTlsFollowerConfigBuilder {
        MpcTlsFollowerConfigBuilder::default()
    }

    /// Returns the common config.
    pub fn common(&self) -> &MpcTlsCommonConfig {
        &self.common
    }
}
