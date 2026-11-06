//! Implementation of an MPC-TLS client.

use crate::{
    deps::{ProverMpc, ProverZk},
    error::Error as TlsnError,
    prover::{
        client::{DecryptState, TlsClient, TlsOutput},
        close::CloseState,
    },
};
use futures::{Future, FutureExt};
use mpc_tls::{MpcTlsLeader, SessionKeys, client::ClientConnection};
use mpz_common::Context;
use rustls_pki_types::CertificateDer;
use std::{
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
};
use tls_core::dns::ServerName;
use tlsn_core::{config::tls::TlsClientConfig, transcript::TlsTranscript};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, instrument, trace, warn};
use webpki::anchor_from_trusted_cert;

type FinalizeFuture =
    Box<dyn Future<Output = Result<(InnerState, Context, TlsTranscript), TlsnError>> + Send>;

pub(crate) struct MpcTlsClient {
    state: State,
    decrypt: Arc<DecryptState>,
    /// Whether the server side must be closed, as opposed to the client side.
    /// This selects which mpc-tls close path to run; the close state itself is
    /// tracked by `close`.
    server_close_requested: bool,
    /// Whether the client close_notify has been given a poll to reach the
    /// transport before the server side is closed.
    client_close_flushed: bool,
    /// Per-direction close state.
    close: CloseState,
    handshaking: bool,
}

enum State {
    Start {
        inner: Box<InnerState>,
    },
    Active {
        inner: Box<InnerState>,
    },
    Busy {
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, TlsnError>> + Send>>,
    },
    CloseActive {
        inner: Box<InnerState>,
    },
    CloseBusy {
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, TlsnError>> + Send>>,
    },
    Finalizing {
        fut: Pin<FinalizeFuture>,
    },
    Finished,
    Error,
}

impl MpcTlsClient {
    pub(crate) fn new(
        keys: SessionKeys,
        vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
        span: Span,
        config: &TlsClientConfig,
        server_name: ServerName,
        mpc_tls: MpcTlsLeader,
    ) -> Result<Self, TlsnError> {
        let config = create_client_config(config)?;
        let decrypt = DecryptState {
            decrypt: AtomicBool::new(mpc_tls.is_decrypting()),
        };

        let tls = ClientConnection::new(Arc::new(config), mpc_tls, server_name).map_err(|e| {
            TlsnError::config()
                .with_msg("failed to create tls client connection")
                .with_source(e)
        })?;

        let inner = InnerState {
            span,
            tls,
            vm,
            keys,
            decrypt: decrypt.is_decrypting(),
            client_closed: false,
        };

        let client = Self {
            decrypt: Arc::new(decrypt),
            server_close_requested: false,
            client_close_flushed: false,
            close: CloseState::new(),
            handshaking: true,
            state: State::Start {
                inner: Box::new(inner),
            },
        };

        Ok(client)
    }

    fn inner_client_mut(&mut self) -> Option<&mut ClientConnection> {
        if let State::Active { inner } | State::CloseActive { inner } = &mut self.state {
            Some(&mut inner.tls)
        } else {
            None
        }
    }

    fn inner_client(&self) -> Option<&ClientConnection> {
        if let State::Active { inner } | State::CloseActive { inner } = &self.state {
            Some(&inner.tls)
        } else {
            None
        }
    }
}

impl TlsClient for MpcTlsClient {
    type Error = TlsnError;

    fn wants_read_tls(&self) -> bool {
        if let Some(client) = self.inner_client() {
            client.wants_read()
        } else {
            false
        }
    }

    fn wants_write_tls(&self) -> bool {
        if let Some(client) = self.inner_client() {
            client.wants_write()
        } else {
            false
        }
    }

    fn read_tls(&mut self, mut buf: &[u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && client.wants_read()
        {
            client.read_tls(&mut buf).map_err(TlsnError::from)
        } else {
            Ok(0)
        }
    }

    fn write_tls(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && client.wants_write()
        {
            client.write_tls(&mut buf).map_err(TlsnError::from)
        } else {
            Ok(0)
        }
    }

    fn wants_read(&self) -> bool {
        if let Some(client) = self.inner_client() {
            !client.plaintext_is_empty()
        } else {
            false
        }
    }

    fn wants_write(&self) -> bool {
        if let Some(client) = self.inner_client() {
            !client.sendable_plaintext_is_full()
        } else {
            false
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && !client.plaintext_is_empty()
        {
            client.read_plaintext(buf).map_err(TlsnError::from)
        } else {
            Ok(0)
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && !client.sendable_plaintext_is_full()
        {
            client
                .write_plaintext(buf)
                .map_err(|err| TlsnError::internal().with_source(err))
        } else {
            Ok(0)
        }
    }

    fn client_close(&mut self) {
        self.close.mark_close_requested();
    }

    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn server_close(&mut self) {
        self.server_close_requested = true;
        self.close.mark_peer_closed();
    }

    fn received_close_notify(&self) -> bool {
        self.close.peer_closed()
    }

    fn decrypt(&self) -> Arc<DecryptState> {
        self.decrypt.clone()
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context,
    ) -> Poll<Result<(Context, ProverZk, TlsOutput), Self::Error>> {
        match std::mem::replace(&mut self.state, State::Error) {
            State::Start { inner } => {
                trace!("inner client is starting");
                self.handshaking = true;
                self.state = State::Busy {
                    fut: Box::pin(inner.start()),
                };
                self.poll(cx)
            }
            State::Active { mut inner } => {
                trace!("inner client is active");
                self.handshaking = inner.tls.is_handshaking();
                if inner.tls.received_close_notify() {
                    self.close.mark_peer_closed();
                }
                let decrypt = self.decrypt.is_decrypting();

                if !inner.tls.is_handshaking() {
                    // If the peer closed its TLS write side, still send our own
                    // close_notify before closing our side. Skipping this makes
                    // the peer observe an abrupt EOF.
                    let peer_sent_close_notify = inner.tls.received_close_notify();
                    let client_close_requested = self.close.close_requested();

                    if inner.client_closed
                        && self.server_close_requested
                        && !self.client_close_flushed
                    {
                        // Give the prover one poll to forward the client
                        // close_notify before the server side closes.
                        self.client_close_flushed = true;
                        self.state = State::Active { inner };
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }

                    if !inner.client_closed
                        && (peer_sent_close_notify
                            || (client_close_requested && !self.server_close_requested))
                    {
                        // Answer the peer's close_notify with our own, or honor
                        // an app close that happened before the peer closed.
                        self.state = State::Busy {
                            fut: Box::pin(inner.client_close()),
                        };
                    } else if self.server_close_requested {
                        self.state = State::CloseBusy {
                            fut: Box::pin(inner.server_close()),
                        };
                    } else if decrypt != inner.decrypt {
                        inner.tls.enable_decryption(decrypt);

                        inner.decrypt = decrypt;
                        self.state = State::Busy {
                            fut: Box::pin(inner.run()),
                        };
                    } else {
                        self.state = State::Busy {
                            fut: Box::pin(inner.run()),
                        };
                    }
                    return self.poll(cx);
                }

                if self.server_close_requested {
                    // A server that disappears mid-handshake leaves nobody to
                    // drive the MPC handshake and no socket to wake on. Without
                    // this the state machine re-polls itself without bound.
                    return Poll::Ready(Err(
                        TlsnError::io().with_msg("server closed during TLS handshake")
                    ));
                }

                self.state = State::Busy {
                    fut: Box::pin(inner.run()),
                };
                self.poll(cx)
            }
            State::Busy { mut fut } => {
                trace!("inner client is busy");

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(inner) => {
                        self.handshaking = inner.tls.is_handshaking();
                        if inner.tls.received_close_notify() {
                            self.close.mark_peer_closed();
                        }
                        self.state = State::Active { inner };
                        // re-poll immediately if a close transition is pending
                        if self.server_close_requested {
                            return self.poll(cx);
                        }
                    }
                    Poll::Pending => self.state = State::Busy { fut },
                }
                Poll::Pending
            }
            State::CloseActive { inner } => {
                trace!("inner client is active closing");
                self.handshaking = false;
                self.state = State::CloseBusy {
                    fut: Box::pin(inner.run()),
                };
                self.poll(cx)
            }
            State::CloseBusy { mut fut } => {
                trace!("inner client is busy closing");

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(mut inner) if inner.is_record_layer_empty() => {
                        // The record layer is empty in both directions: every
                        // outbound byte has been flushed and every inbound
                        // plaintext byte has been delivered. The peer may have
                        // closed first, in which case no client close_notify
                        // was requested; record the closing transition anyway.
                        self.close.mark_close_requested();
                        self.close.mark_outbound_flushed();
                        self.close.mark_drained();
                        debug_assert!(self.close.can_finalize());

                        let (ctx, transcript) =
                            inner.tls.finish().expect("connection should be closed");
                        self.state = State::Finalizing {
                            fut: Box::pin(inner.finalize(ctx, transcript)),
                        };
                        self.poll(cx)
                    }
                    Poll::Ready(inner) => {
                        // There is still buffered plaintext to drain, so the
                        // next poll must drive CloseActive. Without this wake a
                        // caller with no further I/O can park here forever.
                        self.state = State::CloseActive { inner };
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => {
                        self.state = State::CloseBusy { fut };
                        Poll::Pending
                    }
                }
            }
            State::Finalizing { mut fut } => match fut.poll_unpin(cx) {
                Poll::Ready(output) => {
                    let (inner, ctx, tls_transcript) = output?;
                    let InnerState { vm, keys, .. } = inner;

                    let (_, vm) = Arc::into_inner(vm)
                        .expect("vm should have only 1 reference")
                        .into_inner()
                        .into_inner();

                    let output = TlsOutput {
                        keys,
                        tls_transcript,
                    };

                    self.state = State::Finished;
                    Poll::Ready(Ok((ctx, vm, output)))
                }
                Poll::Pending => {
                    self.state = State::Finalizing { fut };
                    Poll::Pending
                }
            },
            State::Finished => Poll::Ready(Err(
                TlsnError::internal().with_msg("mpc tls client polled again in finished state")
            )),
            State::Error => Poll::Ready(Err(
                TlsnError::internal().with_msg("mpc tls client is in error state")
            )),
        }
    }
}

struct InnerState {
    span: Span,
    tls: ClientConnection,
    vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    keys: SessionKeys,
    decrypt: bool,
    client_closed: bool,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn start(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        self.tls
            .start()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "trace", skip_all, err)]
    async fn run(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        let mut state = self
            .tls
            .process_new_packets()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        loop {
            let new_state = self
                .tls
                .process_new_packets()
                .await
                .map_err(|err| TlsnError::internal().with_source(err))?;

            if new_state.plaintext_bytes_to_read() == state.plaintext_bytes_to_read()
                && new_state.tls_bytes_to_write() == state.tls_bytes_to_write()
            {
                break;
            }
            state = new_state;
        }

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn client_close(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        self = self.run().await?;

        if !self.client_closed {
            debug!("sending close notify");
            if let Err(e) = self.tls.send_close_notify().await {
                warn!("failed to send close_notify to server: {}", e);
            }
            self.client_closed = true;

            // Flush the alert before a subsequent server_close can tear the
            // connection down.
            self = self.run().await?;
        }

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn server_close(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        self = self.run().await?;

        self.tls
            .server_closed()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        debug!("closed connection serverside");

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn finalize(
        self,
        mut ctx: Context,
        transcript: TlsTranscript,
    ) -> Result<(Self, Context, TlsTranscript), TlsnError> {
        {
            let mut vm = self.vm.try_lock().expect("VM should not be locked");

            // Finalize DEAP.
            vm.finalize(&mut ctx)
                .await
                .map_err(|err| TlsnError::internal().with_source(err))?;

            debug!("mpc finalized");
        }

        debug!("MPC-TLS done");
        Ok((self, ctx, transcript))
    }

    fn is_record_layer_empty(&self) -> bool {
        self.tls.plaintext_is_empty() && self.tls.is_empty()
    }
}

fn create_client_config(
    config: &TlsClientConfig,
) -> Result<mpc_tls::client::ClientConfig, TlsnError> {
    let root_store = mpc_tls::client::RootCertStore {
        roots: config
            .root_store()
            .roots
            .iter()
            .map(|cert| {
                let der = CertificateDer::from_slice(&cert.0);
                anchor_from_trusted_cert(&der)
                    .map(|anchor| anchor.to_owned())
                    .map_err(|e| {
                        TlsnError::config()
                            .with_msg("failed to parse root certificate")
                            .with_source(e)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };

    let client_config = if let Some((cert, key)) = config.client_auth() {
        mpc_tls::client::ClientConfig::new_with_client_auth(
            root_store,
            cert.iter()
                .map(|cert| mpc_tls::client::Certificate(cert.0.clone()))
                .collect(),
            mpc_tls::client::PrivateKey(key.0.clone()),
        )
        .map_err(|e| {
            TlsnError::config()
                .with_msg("failed to configure client authentication")
                .with_source(e)
        })?
    } else {
        mpc_tls::client::ClientConfig::new(root_store)
    };

    Ok(client_config)
}
