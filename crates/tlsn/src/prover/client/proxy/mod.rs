use crate::{
    Error as TlsnError, Role,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient, TlsOutput},
    proxy::{ProxyProver, TlsParser},
};
use futures::FutureExt;
use mpz_common::Context;
use rustls::{CipherSuite, ClientConnection, NamedGroup, RootCertStore, crypto::CryptoProvider};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
};
use tls_core::dns::ServerName;
use tlsn_core::config::tls::TlsClientConfig;
use tracing::{debug, trace};
use webpki::anchor_from_trusted_cert;

mod kx;
use kx::{InterceptingKxGroup, Pms};

mod prf;
use prf::{VerifyData, create_intercepting_suites};

const ALLOWED_GROUPS: &[NamedGroup] = &[NamedGroup::secp256r1];
const ALLOWED_SUITES: &[CipherSuite] = &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];

pub(crate) struct ProxyTlsClient {
    conn: ClientConnection,
    parser: TlsParser,
    decrypt: Arc<DecryptState>,
    decrypt_mark: Option<usize>,
    client_closed: bool,
    server_closed: bool,
    pms: Pms,
    verify_data: VerifyData,
    state: State,
}

enum State {
    Init {
        prover: ProxyProver,
    },
    Handshaking {
        prover: ProxyProver,
    },
    Connected {
        sent_close_notify: bool,
        prover: ProxyProver,
    },
    Finalizing {
        fut: Pin<FinalizeFuture>,
    },
    Error,
}

type FinalizeFuture =
    Box<dyn Future<Output = Result<(Context, ProverZk, TlsOutput), TlsnError>> + Send + 'static>;

impl ProxyTlsClient {
    pub(crate) fn new(
        prover: ProxyProver,
        config: &TlsClientConfig,
        server_name: ServerName,
    ) -> Result<Self, TlsnError> {
        let pms = Pms::default();
        let verify_data = VerifyData::default();

        let provider = rustls::crypto::aws_lc_rs::default_provider();

        let kx_groups =
            InterceptingKxGroup::from_allowed_groups(&provider, pms.clone(), ALLOWED_GROUPS);
        let cipher_suites =
            create_intercepting_suites(&provider, verify_data.clone(), ALLOWED_SUITES);
        let provider = CryptoProvider {
            kx_groups,
            cipher_suites,
            ..provider
        };

        let config = create_client_config(config, provider)?;
        let conn = ClientConnection::new(Arc::new(config), server_name.into_pki_server_name())?;

        let decrypt = !prover.defer_decryption_from_start();
        let decrypt = DecryptState {
            decrypt: AtomicBool::new(decrypt),
        };

        let parser = TlsParser::new(Role::Prover);

        let tls_client = Self {
            conn,
            parser,
            decrypt: Arc::new(decrypt),
            client_closed: false,
            server_closed: false,
            decrypt_mark: None,
            pms,
            verify_data,
            state: State::Init { prover },
        };

        Ok(tls_client)
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
        let n = self
            .conn
            .read_tls(&mut reader)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.parser.extend_tls_recv(&buf[..n]);
        Ok(n)
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = buf as &mut [u8];
        let n = self
            .conn
            .write_tls(&mut writer)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.parser.extend_tls_sent(&buf[..n]);
        Ok(n)
    }

    fn wants_read(&self) -> bool {
        !self.server_closed
    }

    fn wants_write(&self) -> bool {
        !self.client_closed
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let recv_app = self.parser.mut_app_recv();
        let old_end = recv_app.len();
        match self.conn.reader().read_to_end(recv_app) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(TlsnError::internal().with_source(e)),
        }

        if self.decrypt.is_decrypting() {
            let remaining = self.decrypt_mark.take().unwrap_or(old_end);
            let mut reader = &recv_app[remaining..];
            let n = reader
                .read(buf)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            if remaining + n < recv_app.len() {
                self.decrypt_mark = Some(remaining + n);
            }
            Ok(n)
        } else {
            Ok(0)
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let reader = buf;
        let n = self
            .conn
            .writer()
            .write(&reader)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.parser.extend_app_sent(&buf[..n]);
        Ok(n)
    }

    fn client_close(&mut self) {
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
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Result<(Context, ProverZk, TlsOutput), Self::Error>> {
        match std::mem::replace(&mut self.state, State::Error) {
            State::Init { prover } => {
                debug!("inner client is starting");
                self.state = State::Handshaking { prover };
                self.poll(cx)
            }
            State::Handshaking { prover } => {
                debug!("inner client is handshaking");
                self.conn.process_new_packets()?;
                if !self.conn.is_handshaking() {
                    let now = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();
                    self.parser.set_time(now);

                    let cf_vd = self
                        .verify_data
                        .client_finished()
                        .expect("client finished should be available");
                    self.parser.set_cf_vd(&cf_vd);
                    let sf_vd = self
                        .verify_data
                        .server_finished()
                        .expect("server finished should be available");
                    self.parser.set_sf_vd(&sf_vd);

                    debug!("inner client is transitioning to connected");
                    self.state = State::Connected {
                        sent_close_notify: false,
                        prover,
                    };
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    self.state = State::Handshaking { prover };
                    Poll::Pending
                }
            }
            State::Connected {
                mut sent_close_notify,
                prover,
            } => {
                trace!("inner client is connected");
                if self.client_closed && !self.server_closed && !sent_close_notify {
                    debug!("sent close notify");
                    self.conn.send_close_notify();
                    sent_close_notify = true;
                }

                self.conn.process_new_packets()?;
                if self.server_closed {
                    let pms = self.pms.get().expect("pms should be available");
                    let cf_hash = self
                        .verify_data
                        .client_handshake_hash()
                        .expect("cf_hash should be available");
                    let sf_hash = self
                        .verify_data
                        .server_handshake_hash()
                        .expect("cf_hash should be available");

                    let tls_transcript = self
                        .parser
                        .build()
                        .map_err(|e| TlsnError::internal().with_source(e))?;

                    let fut = Box::pin(prover.finalize(pms, cf_hash, sf_hash, tls_transcript));
                    self.state = State::Finalizing { fut };

                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    self.state = State::Connected {
                        sent_close_notify,
                        prover,
                    };
                    Poll::Pending
                }
            }
            State::Finalizing { mut fut } => {
                debug!("inner client is finalizing");
                match fut.poll_unpin(cx)? {
                    Poll::Ready(output) => Poll::Ready(Ok(output)),
                    Poll::Pending => {
                        self.state = State::Finalizing { fut };
                        Poll::Pending
                    }
                }
            }
            State::Error => Poll::Ready(Err(
                TlsnError::internal().with_msg("tls proxy client is in error state")
            )),
        }
    }
}

fn create_client_config(
    config: &TlsClientConfig,
    provider: CryptoProvider,
) -> Result<rustls::ClientConfig, TlsnError> {
    let mut root_store = RootCertStore::empty();
    for cert in &config.root_store().roots {
        let der = CertificateDer::from_slice(&cert.0);
        let anchor = anchor_from_trusted_cert(&der)
            .map_err(|e| {
                TlsnError::config()
                    .with_msg("failed to parse root certificate")
                    .with_source(e)
            })?
            .to_owned();
        root_store.roots.push(anchor);
    }

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|e| {
            TlsnError::config()
                .with_msg("failed to set protocol versions")
                .with_source(e)
        })?
        .with_root_certificates(root_store);

    let rustls_config = if let Some((cert, key)) = config.client_auth() {
        builder
            .with_client_auth_cert(
                cert.iter()
                    .map(|cert| CertificateDer::from(cert.0.clone()))
                    .collect(),
                PrivateKeyDer::try_from(key.0.clone()).map_err(|e| {
                    TlsnError::config()
                        .with_msg("failed to parse private key")
                        .with_source(e)
                })?,
            )
            .map_err(|e| {
                TlsnError::config()
                    .with_msg("failed to configure client authentication")
                    .with_source(e)
            })?
    } else {
        builder.with_no_client_auth()
    };

    Ok(rustls_config)
}
