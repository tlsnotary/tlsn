use mpz_ot::{chou_orlandi, kos};
use mpz_share_conversion::{ReceiverConfig, SenderConfig};
use std::fmt::{Debug, Formatter, Result};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    verify::WebPkiVerifier,
};
use tls_mpc::{MpcTlsCommonConfig, MpcTlsFollowerConfig};

const DEFAULT_MAX_TRANSCRIPT_SIZE: usize = 1 << 14; // 16Kb
pub(crate) const MAX_TIME_DIFF: u64 = 10; // 10 seconds

/// Configuration for the [`Verifier`](crate::tls::Verifier)
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    #[builder(setter(into))]
    id: String,

    /// Maximum transcript size in bytes
    ///
    /// This includes the number of bytes sent and received to the server.
    #[builder(default = "DEFAULT_MAX_TRANSCRIPT_SIZE")]
    max_transcript_size: usize,
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
            .field("max_transcript_size", &self.max_transcript_size)
            .field("cert_verifier", &"_")
            .finish()
    }
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

    /// Get the certificate verifier.
    pub fn cert_verifier(&self) -> &WebPkiVerifier {
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
                    .max_transcript_size(self.max_transcript_size)
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

fn default_cert_verifier() -> WebPkiVerifier {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));
    WebPkiVerifier::new(root_store, None)
}
