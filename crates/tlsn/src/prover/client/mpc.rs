//! Implementation of an MPC-TLS client.

use crate::{
    deps::{ProverMpc, ProverZk},
    error::Error as TlsnError,
    prover::client::{DecryptState, TlsClient, TlsOutput},
};
use futures::{Future, FutureExt};
use mpc_tls::{ClientConfig, MpcTlsLeader, SessionKeys};
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
    client_wants_close: bool,
    server_closed: bool,
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
        let client_config = Arc::new(create_client_config(config)?);
        let decrypt = DecryptState {
            decrypt: AtomicBool::new(mpc_tls.is_decrypting()),
        };

        let inner = InnerState {
            span,
            tls: mpc_tls,
            client_config,
            server_name,
            vm,
            keys,
            decrypt: decrypt.is_decrypting(),
            client_closed: false,
        };

        let client = Self {
            decrypt: Arc::new(decrypt),
            client_wants_close: false,
            server_closed: false,
            state: State::Start {
                inner: Box::new(inner),
            },
        };

        Ok(client)
    }

    fn inner_client_mut(&mut self) -> Option<&mut MpcTlsLeader> {
        if let State::Active { inner } | State::CloseActive { inner } = &mut self.state {
            Some(&mut inner.tls)
        } else {
            None
        }
    }

    fn inner_client(&self) -> Option<&MpcTlsLeader> {
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
        self.client_wants_close = true;
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
    ) -> Poll<Result<(Context, ProverZk, TlsOutput), Self::Error>> {
        match std::mem::replace(&mut self.state, State::Error) {
            State::Start { inner } => {
                trace!("inner client is starting");
                self.state = State::Busy {
                    fut: Box::pin(inner.start()),
                };
                self.poll(cx)
            }
            State::Active { mut inner } => {
                trace!("inner client is active");
                let decrypt = self.decrypt.is_decrypting();

                if !inner.tls.is_handshaking() {
                    if self.server_closed {
                        self.state = State::CloseBusy {
                            fut: Box::pin(inner.server_close()),
                        };
                    } else if self.client_wants_close {
                        self.state = State::Busy {
                            fut: Box::pin(inner.client_close()),
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
                self.state = State::Busy {
                    fut: Box::pin(inner.run()),
                };
                self.poll(cx)
            }
            State::Busy { mut fut } => {
                trace!("inner client is busy");

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(inner) => {
                        self.state = State::Active { inner };
                        // re-poll immediately if a close transition is pending
                        if self.server_closed {
                            return self.poll(cx);
                        }
                    }
                    Poll::Pending => self.state = State::Busy { fut },
                }
                Poll::Pending
            }
            State::CloseActive { inner } => {
                trace!("inner client is active closing");
                self.state = State::CloseBusy {
                    fut: Box::pin(inner.run()),
                };
                self.poll(cx)
            }
            State::CloseBusy { mut fut } => {
                trace!("inner client is busy closing");

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(mut inner) if inner.is_record_layer_empty() => {
                        let (ctx, transcript) =
                            inner.tls.finish().expect("connection should be closed");
                        self.state = State::Finalizing {
                            fut: Box::pin(inner.finalize(ctx, transcript)),
                        };
                        self.poll(cx)
                    }
                    Poll::Ready(inner) => {
                        cx.waker().wake_by_ref();
                        self.state = State::CloseActive { inner };
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
    tls: MpcTlsLeader,
    client_config: Arc<ClientConfig>,
    server_name: ServerName,
    vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    keys: SessionKeys,
    decrypt: bool,
    client_closed: bool,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn start(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        let client_config = self.client_config.clone();
        let server_name = self.server_name.clone();
        self.tls
            .start(client_config, server_name)
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

fn create_client_config(config: &TlsClientConfig) -> Result<mpc_tls::ClientConfig, TlsnError> {
    let root_store = mpc_tls::RootCertStore {
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
        mpc_tls::ClientConfig::new_with_client_auth(
            root_store,
            cert.iter()
                .map(|cert| mpc_tls::Certificate(cert.0.clone()))
                .collect(),
            mpc_tls::PrivateKey(key.0.clone()),
        )
        .map_err(|e| {
            TlsnError::config()
                .with_msg("failed to configure client authentication")
                .with_source(e)
        })?
    } else {
        mpc_tls::ClientConfig::new(root_store)
    };

    Ok(client_config)
}
