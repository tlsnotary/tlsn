use mpz_ot::{chou_orlandi, kos};
use mpz_share_conversion::{ReceiverConfig, SenderConfig};
use tls_mpc::{MpcTlsCommonConfig, MpcTlsFollowerConfig};

const DEFAULT_MAX_TRANSCRIPT_SIZE: usize = 1 << 14; // 16Kb

/// Configuration for the [`Verifier`](crate::Verifier)
#[allow(missing_docs)]
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct VerifierConfig {
    #[builder(setter(into))]
    id: String,

    /// Maximum transcript size in bytes
    ///
    /// This includes the number of bytes sent and received to the server.
    #[builder(default = "DEFAULT_MAX_TRANSCRIPT_SIZE")]
    max_transcript_size: usize,
}

impl VerifierConfig {
    /// Create a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
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

    pub(crate) fn build_mpc_tls_config(&self) -> MpcTlsFollowerConfig {
        MpcTlsFollowerConfig::builder()
            .common(
                MpcTlsCommonConfig::builder()
                    .id(format!("{}/mpc_tls", &self.id))
                    .max_transcript_size(self.max_transcript_size)
                    .handshake_commit(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    pub(crate) fn ot_count(&self) -> usize {
        self.max_transcript_size * 8
    }

    pub(crate) fn build_p256_sender_config(&self) -> SenderConfig {
        SenderConfig::builder().id("p256/1").build().unwrap()
    }

    pub(crate) fn build_p256_receiver_config(&self) -> ReceiverConfig {
        ReceiverConfig::builder().id("p256/0").build().unwrap()
    }

    pub(crate) fn build_gf2_config(&self) -> ReceiverConfig {
        ReceiverConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap()
    }
}
