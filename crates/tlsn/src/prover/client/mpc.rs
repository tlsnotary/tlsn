//! Implementation of an MPC-TLS client.

use crate::{
    deps::{ProverMpc, ProverZk},
    error::Error as TlsnError,
    prover::client::{DecryptState, TlsClient, TlsOutput},
    tag::verify_tags,
};
use futures::{Future, FutureExt, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use mpz_vm_core::Execute;
use std::{
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
};
use tls_client::{ClientConfig, ClientConnection, ServerName};
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, instrument, trace, warn};

pub(crate) type MpcFuture =
    Box<dyn Future<Output = Result<(Context, TlsTranscript), TlsnError>> + Send>;

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
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
    },
    Active {
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
    },
    Busy {
        mpc: Pin<MpcFuture>,
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, TlsnError>> + Send>>,
    },
    MpcStop {
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
    },
    CloseBusy {
        mpc: Pin<MpcFuture>,
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, TlsnError>> + Send>>,
    },
    Finishing {
        ctx: Context,
        transcript: Box<TlsTranscript>,
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
        span: Span,
        keys: SessionKeys,
        mpc_tls: MpcTlsLeader,
        vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
        config: ClientConfig,
        server_name: ServerName,
    ) -> Result<Self, TlsnError> {
        let decrypt = mpc_tls.is_decrypting();
        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let tls = ClientConnection::new(Arc::new(config), Box::new(mpc_ctrl.clone()), server_name)
            .map_err(|e| {
                TlsnError::config()
                    .with_msg("failed to create tls client connection")
                    .with_source(e)
            })?;

        let inner = InnerState {
            span,
            tls,
            vm,
            keys,
            mpc_ctrl,
            client_closed: false,
            mpc_stopped: false,
            decrypt,
        };

        let decrypt = DecryptState {
            decrypt: AtomicBool::new(decrypt),
        };

        let mpc_tls_client = Self {
            decrypt: Arc::new(decrypt),
            client_wants_close: false,
            server_closed: false,
            state: State::Start {
                mpc: Box::pin(mpc_fut.map_err(TlsnError::from)),
                inner: Box::new(inner),
            },
        };
        Ok(mpc_tls_client)
    }

    fn inner_client_mut(&mut self) -> Option<&mut ClientConnection> {
        if let State::Active { inner, .. } | State::MpcStop { inner, .. } = &mut self.state
            && !inner.mpc_stopped
        {
            Some(&mut inner.tls)
        } else {
            None
        }
    }

    fn inner_client(&self) -> Option<&ClientConnection> {
        if let State::Active { inner, .. } | State::MpcStop { inner, .. } = &self.state
            && !inner.mpc_stopped
        {
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

    fn poll(&mut self, cx: &mut std::task::Context) -> Poll<Result<TlsOutput, Self::Error>> {
        match std::mem::replace(&mut self.state, State::Error) {
            State::Start { mpc, inner } => {
                trace!("inner client is starting");
                self.state = State::Busy {
                    mpc,
                    fut: Box::pin(inner.start()),
                };
                self.poll(cx)
            }
            State::Active { mpc, inner } => {
                trace!("inner client is active");
                let decrypt = self.decrypt.is_decrypting();

                if !inner.tls.is_handshaking() {
                    if self.server_closed {
                        self.state = State::CloseBusy {
                            mpc,
                            fut: Box::pin(inner.server_close()),
                        };
                    } else if self.client_wants_close {
                        self.state = State::Busy {
                            mpc,
                            fut: Box::pin(inner.client_close()),
                        };
                    } else if decrypt != inner.decrypt {
                        self.state = State::Busy {
                            mpc,
                            fut: Box::pin(inner.set_decrypt(decrypt)),
                        };
                    } else {
                        self.state = State::Busy {
                            mpc,
                            fut: Box::pin(inner.run()),
                        };
                    }
                    return self.poll(cx);
                }
                self.state = State::Busy {
                    mpc,
                    fut: Box::pin(inner.run()),
                };
                self.poll(cx)
            }
            State::Busy { mut mpc, mut fut } => {
                trace!("inner client is busy");

                let mpc_poll = mpc.as_mut().poll(cx)?;

                assert!(
                    matches!(mpc_poll, Poll::Pending),
                    "mpc future should not be finished here"
                );

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(inner) => {
                        self.state = State::Active { mpc, inner };
                    }
                    Poll::Pending => self.state = State::Busy { mpc, fut },
                }
                Poll::Pending
            }
            State::MpcStop { mpc, inner } => {
                trace!("inner client is stopping mpc");
                self.state = State::CloseBusy {
                    mpc,
                    fut: Box::pin(inner.stop()),
                };
                self.poll(cx)
            }
            State::CloseBusy { mut mpc, mut fut } => {
                trace!("inner client is busy closing");
                match (mpc.poll_unpin(cx)?, fut.poll_unpin(cx)?) {
                    (Poll::Ready((ctx, transcript)), Poll::Ready(inner)) => {
                        self.state = State::Finalizing {
                            fut: Box::pin(inner.finalize(ctx, transcript)),
                        };
                        self.poll(cx)
                    }
                    (Poll::Pending, Poll::Ready(inner)) => {
                        self.state = State::MpcStop { mpc, inner };
                        Poll::Pending
                    }
                    (Poll::Ready((ctx, transcript)), Poll::Pending) => {
                        self.state = State::Finishing {
                            ctx,
                            transcript: Box::new(transcript),
                            fut,
                        };
                        Poll::Pending
                    }
                    (Poll::Pending, Poll::Pending) => {
                        self.state = State::CloseBusy { mpc, fut };
                        Poll::Pending
                    }
                }
            }
            State::Finishing {
                ctx,
                transcript,
                mut fut,
            } => {
                trace!("inner client is finishing");
                if let Poll::Ready(inner) = fut.poll_unpin(cx)? {
                    self.state = State::Finalizing {
                        fut: Box::pin(inner.finalize(ctx, *transcript)),
                    };
                    self.poll(cx)
                } else {
                    self.state = State::Finishing {
                        ctx,
                        transcript,
                        fut,
                    };
                    Poll::Pending
                }
            }
            State::Finalizing { mut fut } => match fut.poll_unpin(cx) {
                Poll::Ready(output) => {
                    let (inner, ctx, tls_transcript) = output?;
                    let InnerState { vm, keys, .. } = inner;

                    let transcript = tls_transcript
                        .to_transcript()
                        .expect("transcript is complete");

                    let (_, vm) = Arc::into_inner(vm)
                        .expect("vm should have only 1 reference")
                        .into_inner()
                        .into_inner();

                    let output = TlsOutput {
                        ctx,
                        vm,
                        keys,
                        tls_transcript,
                        transcript,
                    };

                    self.state = State::Finished;
                    Poll::Ready(Ok(output))
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
    mpc_ctrl: LeaderCtrl,
    decrypt: bool,
    client_closed: bool,
    mpc_stopped: bool,
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
        self.tls
            .process_new_packets()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn set_decrypt(mut self: Box<Self>, enable: bool) -> Result<Box<Self>, TlsnError> {
        self.mpc_ctrl
            .enable_decryption(enable)
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        self.decrypt = enable;
        self.run().await
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn client_close(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        self.tls
            .process_new_packets()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;

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
        self.tls
            .process_new_packets()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        self.tls
            .server_closed()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        debug!("closed connection serverside");

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn stop(mut self: Box<Self>) -> Result<Box<Self>, TlsnError> {
        if !self.mpc_stopped {
            self.tls
                .process_new_packets()
                .await
                .map_err(|err| TlsnError::internal().with_source(err))?;

            if self.tls.plaintext_is_empty()
                && self
                    .tls
                    .is_empty()
                    .await
                    .map_err(|err| TlsnError::internal().with_source(err))?
            {
                self.mpc_ctrl.stop().await?;
                self.mpc_stopped = true;
                debug!("stopped mpc");
            }
        }

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

            // Pull out ZK VM.
            let mut zk = vm.zk();

            // Prove tag verification of received records.
            // The prover drops the proof output.
            let _ = verify_tags(
                &mut *zk,
                (self.keys.server_write_key, self.keys.server_write_iv),
                self.keys.server_write_mac_key,
                *transcript.version(),
                transcript.recv().to_vec(),
            )
            .map_err(|err| TlsnError::internal().with_source(err))?;
            debug!("verified tags from server");

            zk.execute_all(&mut ctx)
                .await
                .map_err(|err| TlsnError::internal().with_source(err))?;
        }

        debug!("MPC-TLS done");
        Ok((self, ctx, transcript))
    }
}
