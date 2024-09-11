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
    /// The "opaque" transcript id, used for parts of the transcript that are not
    /// part of the application data.
    opaque_id: String,
    /// The maximum length of the transcript in bytes for en-/decryption during the MPC-TLS connection.
    max_online_size: usize,
    /// Maximum number of bytes that will be decrypted after the TLS connection is closed.
    max_deferred_size: usize,
}

impl TranscriptConfig {
    /// Creates a new default builder for the sent transcript config.
    pub fn default_tx() -> TranscriptConfigBuilder {
        let mut builder = TranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_TX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_TX_TRANSCRIPT_ID.to_string())
            .max_online_size(DEFAULT_TRANSCRIPT_MAX_SIZE)
            .max_deferred_size(0);

        builder
    }

    /// Creates a new default builder for the received transcript config.
    pub fn default_rx() -> TranscriptConfigBuilder {
        let mut builder = TranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_RX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_RX_TRANSCRIPT_ID.to_string())
            .max_online_size(0)
            .max_deferred_size(DEFAULT_TRANSCRIPT_MAX_SIZE);

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

    /// Returns the maximum online length of the transcript in bytes.
    pub fn max_online_size(&self) -> usize {
        self.max_online_size
    }

    /// Returns the maximum number of bytes that will be decrypted after the TLS connection is closed.
    pub fn max_deferred_size(&self) -> usize {
        self.max_deferred_size
    }
}

/// Configuration options which are common to both the leader and the follower
#[derive(Debug, Clone, Builder)]
pub struct MpcTlsCommonConfig {
    /// The id of the tls session.
    #[builder(setter(into))]
    id: String,
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

    /// Returns the id of the tls session.
    pub fn id(&self) -> &str {
        &self.id
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
    /// Defers the decryption from the start of the connection until after the connection is closed.
    ///
    /// Decryption of responses will be deferred until after the TLS connection is closed. This is
    /// useful if you either have only one request/response cycle of if you have several such
    /// cycles but the content of the request never depends on the content of the previous response.
    ///
    /// This allows to decrypt responses locally without MPC, so this option saves bandwidth
    /// and performance.
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

    /// Returns if deferred decryption is used from the start of the connection.
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
