use derive_builder::Builder;

static DEFAULT_OPAQUE_TX_TRANSCRIPT_ID: &str = "opaque_tx";
static DEFAULT_OPAQUE_RX_TRANSCRIPT_ID: &str = "opaque_rx";
static DEFAULT_TX_TRANSCRIPT_ID: &str = "tx";
static DEFAULT_RX_TRANSCRIPT_ID: &str = "rx";

#[derive(Debug, Clone, Builder)]
pub struct MpcTlsCommonConfig {
    /// The id of the tls session.
    #[builder(setter(into))]
    id: String,
    /// The number of threads to use
    #[builder(default = "8")]
    num_threads: usize,
    /// Tx transcript ID
    #[builder(setter(into), default = "DEFAULT_TX_TRANSCRIPT_ID.to_string()")]
    tx_transcript_id: String,
    /// Rx transcript ID
    #[builder(setter(into), default = "DEFAULT_RX_TRANSCRIPT_ID.to_string()")]
    rx_transcript_id: String,
    /// Opaque Tx transcript ID
    #[builder(setter(into), default = "DEFAULT_OPAQUE_TX_TRANSCRIPT_ID.to_string()")]
    opaque_tx_transcript_id: String,
    /// Opaque Rx transcript ID
    #[builder(setter(into), default = "DEFAULT_OPAQUE_RX_TRANSCRIPT_ID.to_string()")]
    opaque_rx_transcript_id: String,

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

    /// Returns the tx transcript id.
    pub fn tx_transcript_id(&self) -> &str {
        &self.tx_transcript_id
    }

    /// Returns the rx transcript id.
    pub fn rx_transcript_id(&self) -> &str {
        &self.rx_transcript_id
    }

    /// Returns the opaque tx transcript id.
    pub fn opaque_tx_transcript_id(&self) -> &str {
        &self.opaque_tx_transcript_id
    }

    /// Returns the opaque rx transcript id.
    pub fn opaque_rx_transcript_id(&self) -> &str {
        &self.opaque_rx_transcript_id
    }

    /// Whether the leader commits to the handshake data.
    pub fn handshake_commit(&self) -> bool {
        self.handshake_commit
    }
}

#[derive(Debug, Clone, Builder)]
pub struct MpcTlsLeaderConfig {
    common: MpcTlsCommonConfig,
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
}

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
