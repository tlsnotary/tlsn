//! Implementation of proxy-TLS client.

use crate::{
    Error as TlsnError,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient, TlsOutput},
    proxy::{ProxyProver, TlsBytes},
};
use futures::FutureExt;
use mpz_common::Context;
use rustls::{
    CipherSuite, ClientConnection, NamedGroup, RootCertStore, SupportedCipherSuite,
    client::Resumption, crypto::CryptoProvider,
};
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

mod keylog;
use keylog::MasterSecretLog;

const ALLOWED_GROUPS: &[NamedGroup] = &[NamedGroup::secp256r1];
const ALLOWED_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
];

pub(crate) struct ProxyTlsClient {
    /// TLS client connection state machine.
    conn: ClientConnection,
    /// Master secret captured during the handshake for finalization.
    ms_log: Arc<MasterSecretLog>,
    /// Connection timestamp, set when the handshake completes.
    time: Option<u64>,
    /// Captured TLS and application traffic for the transcript.
    traffic: TlsBytes,
    /// Whether the application client closed its side.
    client_closed: bool,
    /// Whether decrypted application data is still waiting to be read.
    plaintext_pending: bool,
    /// Whether the server transport closed abruptly (EOF/BrokenPipe).
    server_closed: bool,
    /// Whether the server sent a TLS close_notify.
    server_tls_closed: bool,
    /// Whether the transport write half should be closed.
    write_shutdown_requested: bool,
    /// Whether the transport write half has been closed.
    write_shutdown_done: bool,
    /// Protocol state machine.
    state: State,
    /// Shared decryption toggle.
    decrypt: Arc<DecryptState>,
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
        let provider = rustls::crypto::ring::default_provider();

        let kx_groups = provider
            .kx_groups
            .iter()
            .filter(|g| ALLOWED_GROUPS.contains(&g.name()))
            .copied()
            .collect();
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

        let ms_log = Arc::new(MasterSecretLog::default());
        let mut config = create_client_config(config, provider)?;
        config.key_log = ms_log.clone();

        let conn = ClientConnection::new(Arc::new(config), server_name.into_pki_server_name())
            .map_err(|err| {
                TlsnError::internal()
                    .with_msg("rustls error")
                    .with_source(err)
            })?;

        let decrypt = DecryptState {
            decrypt: AtomicBool::new(true),
        };

        let tls_client = Self {
            conn,
            ms_log,
            time: None,
            traffic: TlsBytes::default(),
            client_closed: false,
            plaintext_pending: false,
            server_closed: false,
            server_tls_closed: false,
            write_shutdown_requested: false,
            write_shutdown_done: false,
            state: State::Init { prover },
            decrypt: Arc::new(decrypt),
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
        self.plaintext_pending = n > 0;

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

    fn is_handshaking(&self) -> bool {
        matches!(self.state, State::Init { .. } | State::Handshaking { .. })
    }

    fn incoming_finished(&self) -> bool {
        self.server_tls_closed || self.server_closed
    }

    fn plaintext_pending(&self) -> bool {
        self.plaintext_pending
    }

    fn server_close(&mut self) {
        self.server_closed = true;
    }

    fn wants_write_shutdown(&self) -> bool {
        self.write_shutdown_requested && !self.write_shutdown_done
    }

    fn write_shutdown_complete(&mut self) {
        self.write_shutdown_done = true;
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
                } else if self.server_closed {
                    Poll::Ready(Err(
                        TlsnError::io().with_msg("server closed during TLS handshake")
                    ))
                } else if self.client_closed {
                    // A client that abandons the handshake leaves no data to
                    // drive rustls and no socket to wake on, so the state
                    // machine would stay pending forever.
                    Poll::Ready(Err(
                        TlsnError::io().with_msg("client closed during TLS handshake")
                    ))
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
                let io_state = self.conn.process_new_packets().map_err(|err| {
                    TlsnError::internal()
                        .with_msg("rustls error")
                        .with_source(err)
                })?;

                self.plaintext_pending = io_state.plaintext_bytes_to_read() > 0;

                if io_state.peer_has_closed() && !self.server_tls_closed {
                    self.server_tls_closed = true;
                    debug!("server closed its TLS write side");
                }

                if self.client_closed && !self.server_closed && !sent_close_notify {
                    debug!("sent close notify");
                    self.conn.send_close_notify();
                    sent_close_notify = true;
                }

                // Once the TLS send side has been flushed, the transport owner
                // may close the write half.
                if (sent_close_notify || self.server_closed) && !self.conn.wants_write() {
                    self.write_shutdown_requested = true;
                }

                if self.write_shutdown_requested && !self.write_shutdown_done {
                    self.state = State::Connected {
                        sent_close_notify,
                        prover,
                    };
                    return Poll::Pending;
                }

                // Send ProxyFinished once, when both directions are finished:
                // the prover's own close_notify has been handed to the proxy
                // stream and the write half is closed, and the server has
                // either sent its TLS close_notify or the proxy stream reached
                // EOF. The counts are final at this point.
                let finalize_now = self.write_shutdown_done
                    && (self.server_tls_closed || self.server_closed);

                if finalize_now {
                    let ms = self.ms_log.take();
                    if ms.is_empty() {
                        return Poll::Ready(Err(
                            TlsnError::internal().with_msg("master secret is not available")
                        ));
                    }
                    let time = self.time.ok_or_else(|| {
                        TlsnError::internal().with_msg("connection timestamp is not set")
                    })?;
                    let traffic = std::mem::take(&mut self.traffic);
                    let tls_sent = traffic.tls_sent.len() as u64;
                    let tls_recv = traffic.tls_recv.len() as u64;

                    let fut = Box::pin(async move {
                        let mut prover = prover;
                        prover.send_finished(tls_sent, tls_recv).await?;
                        prover.finalize(ms, time, traffic).await
                    });

                    self.state = State::Finalizing { fut };
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

    // disable session resumption, due to more complicated security assumptions
    rustls_config.resumption = Resumption::disabled();

    Ok(rustls_config)
}
