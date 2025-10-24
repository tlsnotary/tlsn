//! Implementation of an MPC-TLS client.

use crate::{
    mux::MuxFuture,
    prover::{
        Mpc, ProverError, Zk,
        client::{TlsClient, TlsOutput},
    },
    tag::verify_tags,
};
use futures::{Future, FutureExt, TryFutureExt, future::FusedFuture};
use mpc_tls::{LeaderCtrl, SessionKeys};
use mpz_common::Context;
use mpz_vm_core::Execute;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Poll, Waker},
};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, error, info, instrument, warn};

pub(crate) type MpcFuture =
    Box<dyn FusedFuture<Output = Result<(mpz_common::Context, TlsTranscript), ProverError>>>;

pub(crate) type TlsFuture = Box<dyn FusedFuture<Output = Result<ClientConnection, ProverError>>>;

pub(crate) struct MpcTlsClient {
    state: ClientState,
}

impl MpcTlsClient {
    pub(crate) fn new(
        span: Span,
        mpc_ctrl: LeaderCtrl,
        tls: ClientConnection,
        mux: MuxFuture,
        mpc: MpcFuture,
        keys: SessionKeys,
        vm: Arc<Mutex<Deap<Mpc, Zk>>>,
    ) -> Self {
        Self {
            state: ClientState::Idle {
                client_close: false,
                server_close: false,
                inner: InnerState {
                    span,
                    mpc_ctrl,
                    tls_client: Some(tls),
                    tls_fut: None,
                    mux_fut: mux,
                    mpc_fut: Box::into_pin(mpc),
                    keys,
                    vm,
                    closed: false,
                    output: None,
                },
                waker: None,
            },
        }
    }
}

impl TlsClient for MpcTlsClient {
    fn can_read_tls(&self) -> bool {
        todo!()
    }

    fn wants_write_tls(&self) -> bool {
        todo!()
    }

    fn read_tls(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        todo!()
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        todo!()
    }

    fn can_read(&self) -> bool {
        todo!()
    }

    fn wants_write(&self) -> bool {
        todo!()
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        todo!()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        todo!()
    }

    fn client_close(&mut self) -> Result<(), std::io::Error> {
        if let ClientState::Idle {
            client_close,
            server_close,
            ..
        } = &mut self.state
        {
            if !*server_close {
                *client_close = true;
            }
            return Ok(());
        }
        Err(std::io::Error::other(
            "unable to close tls connection, poll again and retry to close",
        ))
    }

    fn server_close(&mut self) -> Result<(), std::io::Error> {
        if let ClientState::Idle {
            client_close,
            server_close,
            ..
        } = &mut self.state
        {
            if !*client_close {
                *server_close = true;
            }
            return Ok(());
        }
        Err(std::io::Error::other(
            "unable to close tls connection, poll again and retry to close",
        ))
    }

    fn poll(&mut self, cx: &mut std::task::Context) -> Poll<Result<(), ProverError>> {
        self.state.poll_unpin(cx)
    }

    fn into_output(&mut self) -> Option<TlsOutput> {
        let state = std::mem::replace(&mut self.state, ClientState::Error);
        match state {
            ClientState::Finished { output } => Some(output),
            _ => {
                self.state = state;
                None
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[project_replace = ClientStateProj]
    #[project = ClientStateProjRef]
    enum ClientState {
        Idle {
            client_close: bool,
            server_close: bool,
            inner: InnerState,
            waker: Option<Waker>
        },
        Running {
            #[pin]
            fut: Pin<Box<dyn Future<Output = Result<InnerState, ProverError>>>>,
        },
        ClientClose {
            #[pin]
            fut: Pin<Box<dyn Future<Output = Result<InnerState, ProverError>>>>,
        },
        ServerClose {
            #[pin]
            fut: Pin<Box<dyn Future<Output = Result<InnerState, ProverError>>>>,
        },
        Finalizing {
            #[pin]
            fut: Pin<Box<dyn Future<Output = Result<InnerState, ProverError>>>>,
        },
        Finished {
            output: TlsOutput
        },
        Error
    }
}

impl Future for ClientState {
    type Output = Result<(), ProverError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut out: Poll<Self::Output> = Poll::Pending;
        let mut new = Self::Error;

        let this = self.as_mut().project();
        match this {
            ClientStateProjRef::Running { mut fut } => match fut.as_mut().poll(cx) {
                Poll::Ready(inner) => {
                    new = Self::Idle {
                        client_close: false,
                        server_close: false,
                        inner: inner?,
                        waker: Some(cx.waker().clone()),
                    };
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::ClientClose { mut fut } => match fut.as_mut().poll(cx) {
                Poll::Ready(inner) => {
                    new = Self::Idle {
                        client_close: true,
                        server_close: false,
                        inner: inner?,
                        waker: Some(cx.waker().clone()),
                    };
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::ServerClose { mut fut } => match fut.as_mut().poll(cx) {
                Poll::Ready(inner) => {
                    new = Self::Idle {
                        client_close: false,
                        server_close: true,
                        inner: inner?,
                        waker: Some(cx.waker().clone()),
                    };
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::Finalizing { mut fut } => match fut.as_mut().poll(cx) {
                Poll::Ready(inner) => {
                    let mut inner = inner?;
                    let (ctx, tls_transcript) =
                        inner.output.take().expect("tls output should be available");
                    let transcript = tls_transcript
                        .to_transcript()
                        .expect("transcript is complete");

                    let (_, vm) = Arc::into_inner(inner.vm)
                        .expect("vm should have only 1 reference")
                        .into_inner()
                        .into_inner();

                    info!("ClientState is finished");
                    new = Self::Finished {
                        output: TlsOutput {
                            mux_fut: inner.mux_fut,
                            ctx,
                            vm,
                            keys: inner.keys,
                            tls_transcript,
                            transcript,
                        },
                    };
                    out = Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::Finished { .. } => {
                panic!("tls client future polled again after completion")
            }
            ClientStateProjRef::Error => panic!("tls client should not arrive in error state"),
            _ => (),
        };

        let this = self.as_mut().project_replace(Self::Error);
        if let ClientStateProj::Idle {
            client_close,
            server_close,
            inner,
            ..
        } = this
        {
            if inner.output.is_some() {
                info!("ClientState is finalizing...");
                new = ClientState::Finalizing {
                    fut: Box::pin(inner.finalize()),
                };
            } else if client_close {
                info!("ClientState is client closing...");
                new = ClientState::ClientClose {
                    fut: Box::pin(inner.client_close()),
                };
            } else if server_close {
                info!("ClientState is server closing...");
                new = ClientState::ServerClose {
                    fut: Box::pin(inner.server_close()),
                };
            } else {
                info!("ClientState is running...");
                new = ClientState::Running {
                    fut: Box::pin(inner.run()),
                };
            }
        }

        self.as_mut().project_replace(new);
        out
    }
}

struct InnerState {
    span: Span,
    mpc_ctrl: LeaderCtrl,
    tls_client: Option<ClientConnection>,
    tls_fut: Option<Pin<TlsFuture>>,
    mpc_fut: Pin<MpcFuture>,
    mux_fut: MuxFuture,
    keys: SessionKeys,
    vm: Arc<Mutex<Deap<Mpc, Zk>>>,

    closed: bool,
    output: Option<(Context, TlsTranscript)>,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn run(mut self) -> Result<Self, ProverError> {
        debug!("running MPC-TLS");

        self.rearm_tls_fut();
        futures::select! {
            tls_finish = &mut self.tls_fut.as_mut().unwrap() => {
                let tls_client = tls_finish?;
                self.tls_client = Some(tls_client);
        },
            mux_finish = &mut self.mux_fut => {
                if let Err(e) = mux_finish {
                    error!("mux error: {:?}", e);
                }
        },
            output = &mut self.mpc_fut => {
                debug!("MPC complete");
                self.output = Some(output?);
                },
        };

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn client_close(mut self) -> Result<Self, ProverError> {
        if self.closed {
            return self.run().await;
        }
        debug!("client closing connection");

        let mut tls = self.wait_for_client().await?;

        if tls.plaintext_is_empty() && tls.is_empty().await? {
            if let Err(e) = tls.send_close_notify().await {
                warn!("failed to send close_notify to server: {}", e);
            };
            self.mpc_ctrl.stop().await?;
            self.closed = true;
        }
        self.tls_client = Some(tls);
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn server_close(mut self) -> Result<Self, ProverError> {
        if self.closed {
            return self.run().await;
        }
        debug!("server closed connection");

        let mut tls = self.wait_for_client().await?;

        if tls.plaintext_is_empty() && tls.is_empty().await? {
            tls.server_closed().await?;
            self.mpc_ctrl.stop().await?;
            self.closed = true;
        }
        self.tls_client = Some(tls);
        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn finalize(mut self) -> Result<Self, ProverError> {
        debug!("finalizing MPC-TLS");
        let (ctx, transcript) = self
            .output
            .as_mut()
            .expect("output of MPC-TLS should be available");

        {
            let mut vm = self.vm.try_lock().expect("VM should not be locked");

            // Finalize DEAP.
            self.mux_fut
                .poll_with(vm.finalize(ctx))
                .await
                .map_err(ProverError::mpc)?;

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

            self.mux_fut
                .poll_with(zk.execute_all(ctx).map_err(ProverError::zk))
                .await?;
        }
        debug!("MPC-TLS done");

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn wait_for_client(&mut self) -> Result<ClientConnection, ProverError> {
        self.rearm_tls_fut();
        loop {
            futures::select! {
                tls_finish = &mut self.tls_fut.as_mut().unwrap() => break tls_finish,
                mux_finish = &mut self.mux_fut => {
                    if let Err(e) = mux_finish {
                        error!("mux error: {:?}", e);
                    }
            },
                output = &mut self.mpc_fut => {
                    debug!("MPC completed");
                    self.output = Some(output?);
                    },
            };
        }
    }

    fn rearm_tls_fut(&mut self) {
        if let Some(tls_fut) = &self.tls_fut
            && !tls_fut.is_terminated()
        {
            return;
        }

        let mut client = self
            .tls_client
            .take()
            .expect("tls client should be available");
        self.tls_fut = Some(Box::pin(
            async {
                client
                    .process_new_packets()
                    .map_err(ProverError::from)
                    .await?;
                Ok::<_, ProverError>(client)
            }
            .fuse(),
        ));
    }
}

/// A controller for the prover.
#[derive(Clone)]
pub struct MpcControl {
    pub(crate) mpc_ctrl: LeaderCtrl,
}

impl MpcControl {
    /// Defers decryption of data from the server until the server has closed
    /// the connection.
    ///
    /// This is a performance optimization which will significantly reduce the
    /// amount of upload bandwidth used by the prover.
    ///
    /// # Notes
    ///
    /// * The prover may need to close the connection to the server in order for
    ///   it to close the connection on its end. If neither the prover or server
    ///   close the connection this will cause a deadlock.
    pub async fn defer_decryption(&self) -> Result<(), ProverError> {
        self.mpc_ctrl
            .defer_decryption()
            .await
            .map_err(ProverError::from)
    }
}
