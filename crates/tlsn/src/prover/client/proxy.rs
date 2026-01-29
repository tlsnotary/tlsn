use crate::{
    Error as TlsnError,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient, TlsOutput},
};
use mpc_tls::SessionKeys;
use mpz_common::Context;
use rustls::{ClientConnection, OwnedTrustAnchor, RootCertStore};
use rustls_pki_types::CertificateDer;
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tls_core::dns::ServerName;
use tlsn_core::{config::tls::TlsClientConfig, transcript::TlsTranscript};
use tracing::Span;
use webpki::anchor_from_trusted_cert;

pub(crate) struct ProxyTlsClient {
    conn: ClientConnection,
    ctx: Context,
    vm: ProverZk,
    decrypt: Arc<DecryptState>,
    client_closed: bool,
    server_closed: bool,
    transcript: TlsTranscript,
}

impl ProxyTlsClient {
    pub(crate) fn new(
        span: Span,
        keys: SessionKeys,
        vm: ProverZk,
        config: &TlsClientConfig,
        server_name: ServerName,
    ) -> Result<Self, TlsnError> {
        let config = create_client_config(config)?;

        todo!()
    }

    fn finalize(self) -> TlsOutput {
        todo!()
    }
}

impl TlsClient for ProxyTlsClient {
    type Error = TlsnError;

    fn wants_read_tls(&self) -> bool {
        self.conn.wants_read()
    }

    fn wants_write_tls(&self) -> bool {
        self.conn.wants_write()
    }

    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut reader = buf;
        self.conn
            .read_tls(&mut reader)
            .map_err(|e| TlsnError::internal().with_source(e))
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = buf as &mut [u8];
        self.conn
            .write_tls(&mut writer)
            .map_err(|e| TlsnError::internal().with_source(e))
    }

    fn wants_read(&self) -> bool {
        !self.server_closed
    }

    fn wants_write(&self) -> bool {
        !self.client_closed
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.conn
            .reader()
            .read(buf)
            .map_err(|e| TlsnError::internal().with_source(e))
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.conn
            .writer()
            .write(buf)
            .map_err(|e| TlsnError::internal().with_source(e))
    }

    fn client_close(&mut self) {
        self.conn.send_close_notify();
        self.client_closed = true;
    }

    fn server_close(&mut self) {
        self.server_closed = true;
    }

    fn decrypt(&self) -> Arc<DecryptState> {
        self.decrypt.clone()
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context,
    ) -> std::task::Poll<Result<super::TlsOutput, Self::Error>> {
        self.conn.process_new_packets()?;
        todo!()
    }
}

fn create_client_config(config: &TlsClientConfig) -> Result<rustls::ClientConfig, TlsnError> {
    let anchors = config
        .root_store()
        .roots
        .iter()
        .map(|cert| {
            let der = CertificateDer::from_slice(&cert.0);
            let anchor = anchor_from_trusted_cert(&der).map_err(|e| {
                TlsnError::config()
                    .with_msg("failed to parse root certificate")
                    .with_source(e)
            })?;
            Ok(OwnedTrustAnchor::from_subject_spki_name_constraints(
                anchor.subject.as_ref(),
                anchor.subject_public_key_info.as_ref(),
                anchor.name_constraints.as_ref().map(|nc| nc.as_ref()),
            ))
        })
        .collect::<Result<Vec<_>, TlsnError>>()?;

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(anchors.into_iter());

    let rustls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store);

    let rustls_config = if let Some((cert, key)) = config.client_auth() {
        rustls_config
            .with_client_auth_cert(
                cert.iter()
                    .map(|cert| rustls::Certificate(cert.0.clone()))
                    .collect(),
                rustls::PrivateKey(key.0.clone()),
            )
            .map_err(|e| {
                TlsnError::config()
                    .with_msg("failed to configure client authentication")
                    .with_source(e)
            })?
    } else {
        rustls_config.with_no_client_auth()
    };

    Ok(rustls_config)
}
