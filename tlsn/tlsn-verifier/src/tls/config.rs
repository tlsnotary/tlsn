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
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
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
            .field("max_sent_data", &self.max_sent_data)
            .field("max_recv_data", &self.max_recv_data)
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

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
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
                            .max_size(self.max_sent_data)
                            .build()
                            .unwrap(),
                    )
                    .rx_config(
                        TranscriptConfig::default_rx()
                            .max_size(self.max_recv_data)
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
        ot_send_estimate(Role::Verifier, self.max_sent_data, self.max_recv_data)
    }

    pub(crate) fn ot_receiver_setup_count(&self) -> usize {
        ot_recv_estimate(Role::Verifier, self.max_sent_data, self.max_recv_data)
    }
}
