//! Implementation of an MPC-TLS client.

use crate::{
    error::Error as TlsnError,
    mpz::{ProverMpc, ProverZk},
    prover::client::{DecryptState, TlsClient, TlsOutput},
    tag::verify_tags,
};
use futures::{Future, FutureExt};
use mpc_tls::{MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use mpz_vm_core::Execute;
use std::{
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, instrument, trace, warn};

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
        tls: ClientConnection<MpcTlsLeader>,
        decrypt: bool,
    ) -> Self {
        let inner = InnerState {
            span,
            tls,
            vm,
            keys,
            decrypt,
            client_closed: false,
        };

        let decrypt = DecryptState {
            decrypt: AtomicBool::new(decrypt),
        };

        Self {
            decrypt: Arc::new(decrypt),
            client_wants_close: false,
            server_closed: false,
            state: State::Start {
                inner: Box::new(inner),
            },
        }
    }

    fn inner_client_mut(&mut self) -> Option<&mut ClientConnection<MpcTlsLeader>> {
        if let State::Active { inner, .. } = &mut self.state {
            Some(&mut inner.tls)
        } else {
            None
        }
    }

    fn inner_client(&self) -> Option<&ClientConnection<MpcTlsLeader>> {
        if let State::Active { inner, .. } = &self.state {
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
                        inner
                            .tls
                            .backend_mut()
                            .enable_decryption(decrypt)
                            .map_err(|err| TlsnError::internal().with_source(err))?;
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
                    }
                    Poll::Pending => self.state = State::Busy { fut },
                }
                Poll::Pending
            }
            State::CloseBusy { mut fut } => {
                trace!("inner client is closing");

                match fut.as_mut().poll(cx)? {
                    Poll::Ready(mut inner) => {
                        let (ctx, transcript) = inner
                            .tls
                            .backend_mut()
                            .finish()
                            .expect("connection should be closed");
                        self.state = State::Finalizing {
                            fut: Box::pin(inner.finalize(ctx, transcript)),
                        };
                        self.poll(cx)
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
    tls: ClientConnection<MpcTlsLeader>,
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
        self.tls
            .process_new_packets()
            .await
            .map_err(|err| TlsnError::internal().with_source(err))?;
        Ok(self)
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
