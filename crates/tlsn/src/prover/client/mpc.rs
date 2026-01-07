//! Implementation of an MPC-TLS client.

use crate::{
    mpz::{ProverMpc, ProverZk},
    prover::{
        ProverError,
        client::{ClientHandle, Command, TlsClient, TlsOutput},
    },
    tag::verify_tags,
};
use futures::{Future, FutureExt};
use mpc_tls::{LeaderCtrl, SessionKeys};
use mpz_common::Context;
use mpz_vm_core::Execute;
use std::{
    pin::Pin,
    sync::{
        Arc,
        mpsc::{Receiver, Sender, channel},
    },
    task::Poll,
};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, instrument, trace, warn};

pub(crate) type MpcFuture =
    Box<dyn Future<Output = Result<(Context, TlsTranscript), ProverError>> + Send>;

type FinalizeFuture =
    Box<dyn Future<Output = Result<(InnerState, Context, TlsTranscript), ProverError>> + Send>;

pub(crate) struct MpcTlsClient {
    sender: Sender<Command>,
    state: State,
    decrypt: bool,
}

enum State {
    Start {
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
        receiver: Receiver<Command>,
    },
    Active {
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
        receiver: Receiver<Command>,
    },
    Busy {
        mpc: Pin<MpcFuture>,
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, ProverError>> + Send>>,
        receiver: Receiver<Command>,
    },
    MpcStop {
        mpc: Pin<MpcFuture>,
        inner: Box<InnerState>,
    },
    CloseBusy {
        mpc: Pin<MpcFuture>,
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, ProverError>> + Send>>,
    },
    Finishing {
        ctx: Context,
        transcript: Box<TlsTranscript>,
        fut: Pin<Box<dyn Future<Output = Result<Box<InnerState>, ProverError>> + Send>>,
    },
    Finalizing {
        fut: Pin<FinalizeFuture>,
    },
    Finished,
    Error,
}

impl MpcTlsClient {
    pub(crate) fn new(
        mpc: MpcFuture,
        keys: SessionKeys,
        vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
        span: Span,
        mpc_ctrl: LeaderCtrl,
        tls: ClientConnection,
        decrypt: bool,
    ) -> Self {
        let inner = InnerState {
            span,
            tls,
            vm,
            keys,
            mpc_ctrl,
            client_closed: false,
            mpc_stopped: false,
        };
        let (sender, receiver) = channel();

        Self {
            sender,
            decrypt,
            state: State::Start {
                receiver,
                mpc: Box::into_pin(mpc),
                inner: Box::new(inner),
            },
        }
    }

    fn inner_client_mut(&mut self) -> Option<&mut ClientConnection> {
        if let State::Active { inner, .. } | State::MpcStop { inner, .. } = &mut self.state {
            Some(&mut inner.tls)
        } else {
            None
        }
    }

    fn inner_client(&self) -> Option<&ClientConnection> {
        if let State::Active { inner, .. } | State::MpcStop { inner, .. } = &self.state {
            Some(&inner.tls)
        } else {
            None
        }
    }
}

impl TlsClient for MpcTlsClient {
    type Error = ProverError;

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
            client.read_tls(&mut buf).map_err(ProverError::from)
        } else {
            Ok(0)
        }
    }

    fn write_tls(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && client.wants_write()
        {
            client.write_tls(&mut buf).map_err(ProverError::from)
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
            client.read_plaintext(buf).map_err(ProverError::from)
        } else {
            Ok(0)
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if let Some(client) = self.inner_client_mut()
            && !client.sendable_plaintext_is_full()
        {
            client.write_plaintext(buf).map_err(ProverError::from)
        } else {
            Ok(0)
        }
    }

    fn client_close(&mut self) -> Result<(), Self::Error> {
        self.sender
            .send(Command::ClientClose)
            .map_err(|_| ProverError::state("unable to close connection clientside"))
    }

    fn server_close(&mut self) -> Result<(), Self::Error> {
        self.sender
            .send(Command::ServerClose)
            .map_err(|_| ProverError::state("unable to close connection serverside"))
    }

    fn handle(&self) -> ClientHandle {
        ClientHandle {
            sender: self.sender.clone(),
        }
    }

    fn poll(&mut self, cx: &mut std::task::Context) -> Poll<Result<TlsOutput, Self::Error>> {
        match std::mem::replace(&mut self.state, State::Error) {
            State::Start {
                mpc,
                inner,
                receiver,
            } => {
                trace!("inner client is starting");
                self.state = State::Busy {
                    mpc,
                    fut: Box::pin(inner.start()),
                    receiver,
                };
                self.poll(cx)
            }
            State::Active {
                mpc,
                inner,
                receiver,
            } => {
                trace!("inner client is active");

                if !inner.tls.is_handshaking()
                    && let Ok(cmd) = receiver.try_recv()
                {
                    match cmd {
                        Command::ClientClose => {
                            self.state = State::Busy {
                                mpc,
                                fut: Box::pin(inner.client_close()),
                                receiver,
                            };
                        }
                        Command::ServerClose => {
                            std::mem::drop(receiver);
                            self.state = State::CloseBusy {
                                mpc,
                                fut: Box::pin(inner.server_close()),
                            };
                        }
                        Command::SetDecrypt(enable) => {
                            self.decrypt = enable;
                            self.state = State::Busy {
                                mpc,
                                fut: Box::pin(inner.set_decrypt(enable)),
                                receiver,
                            };
                        }
                        Command::IsDecrypting(sender) => {
                            _ = sender.send(self.decrypt);
                            self.state = State::Busy {
                                mpc,
                                fut: Box::pin(inner.run()),
                                receiver,
                            };
                        }
                    }
                } else {
                    self.state = State::Busy {
                        mpc,
                        fut: Box::pin(inner.run()),
                        receiver,
                    };
                }
                self.poll(cx)
            }
            State::Busy {
                mut mpc,
                mut fut,
                receiver,
            } => {
                trace!("inner client is busy");

                let mpc_poll = mpc.as_mut().poll(cx)?;

                assert!(
                    matches!(mpc_poll, Poll::Pending),
                    "mpc future should not be finished here"
                );

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(inner) => {
                        self.state = State::Active {
                            mpc,
                            inner,
                            receiver,
                        };
                    }
                    Poll::Pending => self.state = State::Busy { mpc, fut, receiver },
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
                match (fut.poll_unpin(cx)?, mpc.poll_unpin(cx)?) {
                    (Poll::Ready(inner), Poll::Ready((ctx, transcript))) => {
                        self.state = State::Finalizing {
                            fut: Box::pin(inner.finalize(ctx, transcript)),
                        };
                        self.poll(cx)
                    }
                    (Poll::Ready(inner), Poll::Pending) => {
                        self.state = State::MpcStop { mpc, inner };
                        Poll::Pending
                    }
                    (Poll::Pending, Poll::Ready((ctx, transcript))) => {
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
            State::Finished => Poll::Ready(Err(ProverError::state(
                "mpc tls client polled again in finished state",
            ))),
            State::Error => {
                Poll::Ready(Err(ProverError::state("mpc tls client is in error state")))
            }
        }
    }
}

struct InnerState {
    span: Span,
    tls: ClientConnection,
    vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    keys: SessionKeys,
    mpc_ctrl: LeaderCtrl,
    client_closed: bool,
    mpc_stopped: bool,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn start(mut self: Box<Self>) -> Result<Box<Self>, ProverError> {
        self.tls.start().await?;
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "trace", skip_all, err)]
    async fn run(mut self: Box<Self>) -> Result<Box<Self>, ProverError> {
        self.tls.process_new_packets().await?;
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn set_decrypt(self: Box<Self>, enable: bool) -> Result<Box<Self>, ProverError> {
        self.mpc_ctrl.enable_decryption(enable).await?;
        self.run().await
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn client_close(mut self: Box<Self>) -> Result<Box<Self>, ProverError> {
        if !self.client_closed {
            debug!("sending close notify");
            if let Err(e) = self.tls.send_close_notify().await {
                warn!("failed to send close_notify to server: {}", e);
            }
            self.client_closed = true;
        }
        self.run().await
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn server_close(mut self: Box<Self>) -> Result<Box<Self>, ProverError> {
        self.tls.process_new_packets().await?;
        self.tls.server_closed().await?;
        debug!("closed connection serverside");

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn stop(mut self: Box<Self>) -> Result<Box<Self>, ProverError> {
        self.tls.process_new_packets().await?;
        if !self.mpc_stopped && self.tls.plaintext_is_empty() && self.tls.is_empty().await? {
            self.mpc_ctrl.stop().await?;
            self.mpc_stopped = true;
            debug!("stopped mpc");
        }

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn finalize(
        self,
        mut ctx: Context,
        transcript: TlsTranscript,
    ) -> Result<(Self, Context, TlsTranscript), ProverError> {
        {
            let mut vm = self.vm.try_lock().expect("VM should not be locked");

            // Finalize DEAP.
            vm.finalize(&mut ctx).await.map_err(ProverError::mpc)?;

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
            .map_err(ProverError::zk)?;
            debug!("verified tags from server");

            zk.execute_all(&mut ctx).await.map_err(ProverError::zk)?
        }

        debug!("MPC-TLS done");
        Ok((self, ctx, transcript))
    }
}
