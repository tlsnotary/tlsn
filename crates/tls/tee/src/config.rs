use derive_builder::Builder;

static DEFAULT_OPAQUE_TX_TRANSCRIPT_ID: &str = "opaque_tx";
static DEFAULT_OPAQUE_RX_TRANSCRIPT_ID: &str = "opaque_rx";
static DEFAULT_TX_TRANSCRIPT_ID: &str = "tx";
static DEFAULT_RX_TRANSCRIPT_ID: &str = "rx";
const DEFAULT_TRANSCRIPT_MAX_SIZE: usize = 1 << 14;

/// Transcript configuration.
#[derive(Debug, Clone, Builder)]
pub struct TeeTranscriptConfig {
    /// The transcript id.
    id: String,
    /// The "opaque" transcript id, used for parts of the transcript that are not
    /// part of the application data.
    opaque_id: String,
    /// The maximum length of the transcript in bytes.
    max_size: usize,
}

impl TeeTranscriptConfig {
    /// Creates a new default builder for the sent transcript config.
    pub fn default_tx() -> TeeTranscriptConfigBuilder {
        let mut builder = TeeTranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_TX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_TX_TRANSCRIPT_ID.to_string())
            .max_size(DEFAULT_TRANSCRIPT_MAX_SIZE);

        builder
    }

    /// Creates a new default builder for the received transcript config.
    pub fn default_rx() -> TeeTranscriptConfigBuilder {
        let mut builder = TeeTranscriptConfigBuilder::default();

        builder
            .id(DEFAULT_RX_TRANSCRIPT_ID.to_string())
            .opaque_id(DEFAULT_OPAQUE_RX_TRANSCRIPT_ID.to_string())
            .max_size(DEFAULT_TRANSCRIPT_MAX_SIZE);

        builder
    }

    /// Creates a new builder for `TranscriptConfig`.
    pub fn builder() -> TeeTranscriptConfigBuilder {
        TeeTranscriptConfigBuilder::default()
    }

    /// Returns the transcript id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the "opaque" transcript id.
    pub fn opaque_id(&self) -> &str {
        &self.opaque_id
    }

    /// Returns the maximum length of the transcript in bytes.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

/// Configuration options which are common to both the leader and the follower
#[derive(Debug, Clone, Builder)]
pub struct TeeTlsCommonConfig {
    /// The id of the tls session.
    #[builder(setter(into))]
    id: String,
    /// The number of threads to use
    #[builder(default = "8")]
    num_threads: usize,
    /// The sent data transcript configuration.
    #[builder(default = "TeeTranscriptConfig::default_tx().build().unwrap()")]
    tx_config: TeeTranscriptConfig,
    /// The received data transcript configuration.
    #[builder(default = "TeeTranscriptConfig::default_rx().build().unwrap()")]
    rx_config: TeeTranscriptConfig,
    /// Whether the leader commits to the handshake data.
    #[builder(default = "true")]
    handshake_commit: bool,
}

impl TeeTlsCommonConfig {
    /// Creates a new builder for `TeeTlsCommonConfig`.
    pub fn builder() -> TeeTlsCommonConfigBuilder {
        TeeTlsCommonConfigBuilder::default()
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
    pub fn tx_config(&self) -> &TeeTranscriptConfig {
        &self.tx_config
    }

    /// Returns the configuration for the received data transcript.
    pub fn rx_config(&self) -> &TeeTranscriptConfig {
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
pub struct TeeTlsLeaderConfig {
    common: TeeTlsCommonConfig,
}

impl TeeTlsLeaderConfig {
    /// Creates a new builder for `TeeTlsLeaderConfig`.
    pub fn builder() -> TeeTlsLeaderConfigBuilder {
        TeeTlsLeaderConfigBuilder::default()
    }

    /// Returns the common config.
    pub fn common(&self) -> &TeeTlsCommonConfig {
        &self.common
    }
}

/// Configuration for the follower
#[allow(missing_docs)]
#[derive(Debug, Clone, Builder)]
pub struct TeeTlsFollowerConfig {
    common: TeeTlsCommonConfig,
}

impl TeeTlsFollowerConfig {
    /// Creates a new builder for `TeeTlsFollowerConfig`.
    pub fn builder() -> TeeTlsFollowerConfigBuilder {
        TeeTlsFollowerConfigBuilder::default()
    }

    /// Returns the common config.
    pub fn common(&self) -> &TeeTlsCommonConfig {
        &self.common
    }
}
