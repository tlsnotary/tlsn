use mpz_ot::{chou_orlandi, kos};
use tls_client::RootCertStore;
use tls_mpc::{MpcTlsCommonConfig, MpcTlsLeaderConfig, TranscriptConfig};
use tlsn_common::config::ProtocolConfig;

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
    /// Protocol configuration to be checked with the verifier.
    protocol_config: ProtocolConfig,
    /// Whether the `deferred decryption` feature is toggled on from the start of the MPC-TLS
    /// connection.
    ///
    /// See `defer_decryption_from_start` in [tls_mpc::MpcTlsLeaderConfig].
    #[builder(default = "true")]
    defer_decryption_from_start: bool,
}

impl ProverConfig {
    /// Create a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns the instance id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the server DNS name.
    pub fn server_dns(&self) -> &str {
        &self.server_dns
    }

    /// Returns the protocol configuration.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns whether the `deferred decryption` feature is toggled on from the start of the MPC-TLS
    /// connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    pub(crate) fn build_mpc_tls_config(&self) -> MpcTlsLeaderConfig {
        MpcTlsLeaderConfig::builder()
            .common(
                MpcTlsCommonConfig::builder()
                    .id(format!("{}/mpc_tls", &self.id))
                    .tx_config(
                        TranscriptConfig::default_tx()
                            .max_online_size(self.protocol_config.max_sent_data())
                            .build()
                            .unwrap(),
                    )
                    .rx_config(
                        TranscriptConfig::default_rx()
                            .max_online_size(self.protocol_config.max_recv_data_online())
                            .max_offline_size(
                                self.protocol_config.max_recv_data()
                                    - self.protocol_config.max_recv_data_online(),
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
