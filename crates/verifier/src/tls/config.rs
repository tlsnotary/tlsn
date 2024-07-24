use mpz_ot::{chou_orlandi, kos};
use std::fmt::{Debug, Formatter, Result};
use tls_core::verify::{ServerCertVerifier, WebPkiVerifier};
use tls_mpc::{MpcTlsCommonConfig, MpcTlsFollowerConfig, TranscriptConfig};
use tlsn_common::{
    config::{ot_recv_estimate, ot_send_estimate, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
    Role,
};
use tlsn_core::proof::default_cert_verifier;

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    #[builder(setter(into))]
    id: String,
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data_online: usize,
    /// Maximum number of bytes that can be sent offline.
    max_sent_data_offline: usize,
    /// Maximum number of bytes that can be received online.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data_online: usize,
    /// Maximum number of bytes that can be received offline.
    max_recv_data_offline: usize,
    #[builder(
        pattern = "owned",
        setter(strip_option),
        default = "Some(default_cert_verifier())"
    )]
    cert_verifier: Option<WebPkiVerifier>,
}

impl Debug for VerifierConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("VerifierConfig")
            .field("id", &self.id)
            .field("max_sent_data_online", &self.max_sent_data_online)
            .field("max_sent_data_offline", &self.max_sent_data_offline)
            .field("max_recv_data_online", &self.max_recv_data_online)
            .field("max_recv_data_offline", &self.max_recv_data_offline)
            .field("cert_verifier", &"_")
            .finish()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the ID of the notarization session.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the maximum number of bytes that can be sent online.
    pub fn max_sent_data_online(&self) -> usize {
        self.max_sent_data_online
    }

    /// Returns the maximum number of bytes that can be sent offline.
    pub fn max_sent_data_offline(&self) -> usize {
        self.max_sent_data_offline
    }

    /// Returns the maximum number of bytes that can be received online.
    pub fn max_recv_data_online(&self) -> usize {
        self.max_recv_data_online
    }

    /// Returns the maximum number of bytes that can be received offline.
    pub fn max_recv_data_offline(&self) -> usize {
        self.max_recv_data_offline
    }

    /// Returns the certificate verifier.
    pub fn cert_verifier(&self) -> &impl ServerCertVerifier {
        self.cert_verifier
            .as_ref()
            .expect("Certificate verifier should be set")
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
                    .tx_config(
                        TranscriptConfig::default_tx()
                            .max_online_size(self.max_sent_data_online)
                            .max_offline_size(self.max_sent_data_offline)
                            .build()
                            .unwrap(),
                    )
                    .rx_config(
                        TranscriptConfig::default_rx()
                            .max_online_size(self.max_recv_data_online)
                            .max_offline_size(self.max_recv_data_offline)
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

    pub(crate) fn ot_sender_setup_count(&self) -> usize {
        ot_send_estimate(
            Role::Verifier,
            self.max_sent_data_online + self.max_sent_data_offline,
            self.max_recv_data_online + self.max_recv_data_offline,
        )
    }

    pub(crate) fn ot_receiver_setup_count(&self) -> usize {
        ot_recv_estimate(
            Role::Verifier,
            self.max_sent_data_online + self.max_sent_data_offline,
            self.max_recv_data_online + self.max_recv_data_offline,
        )
    }
}
