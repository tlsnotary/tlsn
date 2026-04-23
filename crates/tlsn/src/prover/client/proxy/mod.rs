//! Implementation of proxy-TLS client.

use crate::{
    Error as TlsnError,
    deps::ProverZk,
    prover::client::{TlsClient, TlsOutput},
    proxy::{ProxyProver, TlsBytes},
};
use futures::FutureExt;
use mpz_common::Context;
use rustls::{
    CipherSuite, ClientConnection, NamedGroup, RootCertStore, SupportedCipherSuite,
    crypto::CryptoProvider,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
    task::Poll,
};
use tls_core::dns::ServerName;
use tlsn_core::config::tls::TlsClientConfig;
use tracing::{debug, trace};
use webpki::anchor_from_trusted_cert;

mod kx;
use kx::{InterceptingKxGroup, take_pms};

const ALLOWED_GROUPS: &[NamedGroup] = &[NamedGroup::secp256r1];
const ALLOWED_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
];

pub(crate) struct ProxyTlsClient {
    conn: ClientConnection,
    time: Option<u64>,
    traffic: TlsBytes,
    client_closed: bool,
    server_closed: bool,
    state: State,
}

enum State {
    Init {
        prover: Box<ProxyProver>,
    },
    Handshaking {
        prover: Box<ProxyProver>,
    },
    Connected {
        sent_close_notify: bool,
        prover: Box<ProxyProver>,
    },
    Finalizing {
        fut: Pin<FinalizeFuture>,
    },
    Error,
}

type FinalizeFuture =
    Box<dyn Future<Output = Result<(Context, ProverZk, TlsOutput), TlsnError>> + Send>;

impl ProxyTlsClient {
    pub(crate) fn new(
        prover: Box<ProxyProver>,
        config: &TlsClientConfig,
        server_name: ServerName,
    ) -> Result<Self, TlsnError> {
        // provider can only be set once per process to work around rustls limitation of
        // static references.
        let provider = rustls::crypto::ring::default_provider();

        let kx_groups = InterceptingKxGroup::from_allowed_groups(&provider, ALLOWED_GROUPS);
        let cipher_suites: Vec<SupportedCipherSuite> = provider
            .cipher_suites
            .iter()
            .filter(|s| match s {
                SupportedCipherSuite::Tls12(tls12) => ALLOWED_SUITES.contains(&tls12.common.suite),
                _ => false,
            })
            .copied()
            .collect();
        let provider = CryptoProvider {
            kx_groups,
            cipher_suites,
            ..provider
        };

        let config = create_client_config(config, provider)?;
        let conn = ClientConnection::new(Arc::new(config), server_name.into_pki_server_name())
            .map_err(|err| {
                TlsnError::internal()
                    .with_msg("rustls error")
                    .with_source(err)
            })?;

        let tls_client = Self {
            conn,
            time: None,
            traffic: TlsBytes::default(),
            client_closed: false,
            server_closed: false,
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
        self.traffic.tls_recv.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = buf as &mut [u8];
        let n = self
            .conn
            .write_tls(&mut writer)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.traffic.tls_sent.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn wants_read(&self) -> bool {
        matches!(self.state, State::Connected { .. })
    }

    fn wants_write(&self) -> bool {
        matches!(
            self.state,
            State::Handshaking { .. } | State::Connected { .. }
        ) && !self.client_closed
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = match self.conn.reader().read(buf) {
            Ok(n) => Ok::<_, TlsnError>(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => return Err(TlsnError::internal().with_source(e)),
        }?;
        self.traffic.app_recv.extend_from_slice(&buf[..n]);

        Ok(n)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let reader = buf;
        let n = self
            .conn
            .writer()
            .write(reader)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.traffic.app_sent.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn client_close(&mut self) {
        self.client_closed = true;
    }

    fn server_close(&mut self) {
        self.server_closed = true;
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
                self.conn.process_new_packets().map_err(|err| {
                    TlsnError::internal()
                        .with_msg("rustls error")
                        .with_source(err)
                })?;
                if !self.conn.is_handshaking() {
                    let now = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();
                    self.time = Some(now);

                    debug!("inner client is transitioning to connected");
                    self.state = State::Connected {
                        sent_close_notify: false,
                        prover,
                    };
                    self.poll(cx)
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
                self.conn.process_new_packets().map_err(|err| {
                    TlsnError::internal()
                        .with_msg("rustls error")
                        .with_source(err)
                })?;

                if self.server_closed {
                    let pms = take_pms();
                    if pms.is_empty() {
                        return Poll::Ready(Err(
                            TlsnError::internal().with_msg("pms is not available")
                        ));
                    }
                    let time = self.time.ok_or_else(|| {
                        TlsnError::internal().with_msg("connection timestamp is not set")
                    })?;
                    let traffic = std::mem::take(&mut self.traffic);

                    let fut = Box::pin(prover.finalize(pms, time, traffic));

                    self.state = State::Finalizing { fut };
                    self.poll(cx)
                } else if self.client_closed && !sent_close_notify {
                    debug!("sent close notify");
                    self.conn.send_close_notify();
                    sent_close_notify = true;

                    self.state = State::Connected {
                        sent_close_notify,
                        prover,
                    };

                    self.poll(cx)
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

    let mut rustls_config = if let Some((cert, key)) = config.client_auth() {
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
    rustls_config.require_ems = true;

    Ok(rustls_config)
}
