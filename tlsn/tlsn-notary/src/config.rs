use mpz_ot::{chou_orlandi, kos};

const DEFAULT_MAX_TRANSCRIPT_SIZE: usize = 1 << 14; // 16Kb

/// Configuration for the [`Notary`](crate::Notary)
#[allow(missing_docs)]
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct NotaryConfig {
    #[builder(setter(into))]
    id: String,

    /// Maximum transcript size in bytes
    ///
    /// This includes the number of bytes sent and received to the server.
    #[builder(default = "DEFAULT_MAX_TRANSCRIPT_SIZE")]
    max_transcript_size: usize,
}

impl NotaryConfig {
    /// Create a new builder for `NotaryConfig`.
    pub fn builder() -> NotaryConfigBuilder {
        NotaryConfigBuilder::default()
    }

    /// Returns the ID of the notarization session.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the maximum transcript size in bytes.
    pub fn max_transcript_size(&self) -> usize {
        self.max_transcript_size
    }

    pub(crate) fn build_base_ot_sender_config(&self) -> chou_orlandi::SenderConfig {
        chou_orlandi::SenderConfig::default()
    }

    pub(crate) fn build_base_ot_receiver_config(&self) -> chou_orlandi::ReceiverConfig {
        chou_orlandi::ReceiverConfig::builder()
            .receiver_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn build_ot_sender_config(&self) -> kos::SenderConfig {
        kos::SenderConfig::builder()
            .sender_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn build_ot_receiver_config(&self) -> kos::ReceiverConfig {
        kos::ReceiverConfig::default()
    }

    pub(crate) fn ot_count(&self) -> usize {
        self.max_transcript_size * 8
    }
}
