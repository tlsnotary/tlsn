use mpz_ot::{chou_orlandi, kos};
use std::{
    fmt::{Debug, Formatter, Result},
    sync::Arc,
};
use tls_mpc::{MpcTlsCommonConfig, MpcTlsFollowerConfig, TranscriptConfig};
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::CryptoProvider;

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    protocol_config_validator: ProtocolConfigValidator,
    /// Cryptography provider.
    #[builder(default, setter(into))]
    crypto_provider: Arc<CryptoProvider>,
}

impl Debug for VerifierConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("VerifierConfig")
            .field("protocol_config_validator", &self.protocol_config_validator)
            .finish_non_exhaustive()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the protocol configuration validator.
    pub fn protocol_config_validator(&self) -> &ProtocolConfigValidator {
        &self.protocol_config_validator
    }

    /// Returns the cryptography provider.
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
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

    pub(crate) fn build_mpc_tls_config(
        &self,
        protocol_config: &ProtocolConfig,
    ) -> MpcTlsFollowerConfig {
        MpcTlsFollowerConfig::builder()
            .common(
                MpcTlsCommonConfig::builder()
                    .tx_config(
                        TranscriptConfig::default_tx()
                            .max_online_size(protocol_config.max_sent_data())
                            .build()
                            .unwrap(),
                    )
                    .rx_config(
                        TranscriptConfig::default_rx()
                            .max_online_size(protocol_config.max_recv_data_online())
                            .max_offline_size(
                                protocol_config.max_recv_data()
                                    - protocol_config.max_recv_data_online(),
                            )
                            .build()
                            .unwrap(),
                    )
                    .handshake_commit(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }
}
