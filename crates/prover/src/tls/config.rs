use mpz_ot::{chou_orlandi, kos};
use tls_client::RootCertStore;
use tls_mpc::{MpcTlsCommonConfig, MpcTlsLeaderConfig, TranscriptConfig};
use tlsn_common::{
    config::{ot_recv_estimate, ot_send_estimate, DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT},
    Role,
};

/// Configuration for the prover
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct ProverConfig {
    /// Id of the notarization session.
    #[builder(setter(into))]
    id: String,
    /// The server DNS name.
    #[builder(setter(into))]
    server_dns: String,
    /// TLS root certificate store.
    #[builder(setter(strip_option), default = "default_root_store()")]
    pub(crate) root_cert_store: RootCertStore,
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
}

impl ProverConfig {
    /// Create a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Returns the server DNS name.
    pub fn server_dns(&self) -> &str {
        &self.server_dns
    }

    pub(crate) fn build_mpc_tls_config(&self) -> MpcTlsLeaderConfig {
        MpcTlsLeaderConfig::builder()
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

    pub(crate) fn build_base_ot_sender_config(&self) -> chou_orlandi::SenderConfig {
        chou_orlandi::SenderConfig::builder()
            .receiver_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn build_base_ot_receiver_config(&self) -> chou_orlandi::ReceiverConfig {
        chou_orlandi::ReceiverConfig::default()
    }

    pub(crate) fn build_ot_sender_config(&self) -> kos::SenderConfig {
        kos::SenderConfig::default()
    }

    pub(crate) fn build_ot_receiver_config(&self) -> kos::ReceiverConfig {
        kos::ReceiverConfig::builder()
            .sender_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn ot_sender_setup_count(&self) -> usize {
        ot_send_estimate(Role::Prover, self.max_sent_data, self.max_recv_data)
    }

    pub(crate) fn ot_receiver_setup_count(&self) -> usize {
        ot_recv_estimate(Role::Prover, self.max_sent_data, self.max_recv_data)
    }
}

/// Default root store using mozilla certs.
fn default_root_store() -> RootCertStore {
    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    root_store
}
