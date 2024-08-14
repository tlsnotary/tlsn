use tls_client::RootCertStore;
use tls_tee::{TeeTlsCommonConfig, TeeTlsLeaderConfig};
use tlsn_common::config::{ DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT};

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

    /// Returns the instance id.
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

    /// Returns the server DNS name.
    pub fn server_dns(&self) -> &str {
        &self.server_dns
    }

    pub(crate) fn build_tee_tls_config(&self) -> TeeTlsLeaderConfig {
        TeeTlsLeaderConfig::builder()
            .common(
                TeeTlsCommonConfig::builder()
                    .id(format!("{}/tee_tls", &self.id))
                    .handshake_commit(true)
                    .build()
                    .unwrap(),
            )
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
