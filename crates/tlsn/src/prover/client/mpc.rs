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
use tracing::{Span, debug, error, info, instrument};

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
        mut tls: ClientConnection,
        mux: MuxFuture,
        mpc: MpcFuture,
        keys: SessionKeys,
        vm: Arc<Mutex<Deap<Mpc, Zk>>>,
    ) -> Self {
        let tls = Box::pin(
            async {
                tls.process_new_packets().map_err(ProverError::from).await?;
                Ok::<_, ProverError>(tls)
            }
            .fuse(),
        );

        Self {
            state: ClientState::Idle {
                inner: InnerState {
                    span,
                    mpc_ctrl,
                    tls,
                    mux,
                    mpc: Box::into_pin(mpc),
                    keys,
                    vm,

                    close: false,
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

    fn close(&mut self) -> Result<(), std::io::Error> {
        if let ClientState::Idle {
            inner: InnerState { close, .. },
            ..
        } = &mut self.state
        {
            *close = true;
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
            inner: InnerState,
            waker: Option<Waker>
        },
        Running {
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
                        inner: inner?,
                        waker: Some(cx.waker().clone()),
                    };
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::Finalizing { mut fut } => match fut.as_mut().poll(cx) {
                Poll::Ready(inner) => {
                    new = Self::Idle {
                        inner: inner?,
                        waker: Some(cx.waker().clone()),
                    };
                }
                Poll::Pending => return Poll::Pending,
            },
            ClientStateProjRef::Error => panic!("tls client should not arrive in error state"),
            _ => (),
        };

        let this = self.as_mut().project_replace(Self::Error);
        match this {
            ClientStateProj::Idle { mut inner, .. } => {
                if inner.close {
                    new = ClientState::Finalizing {
                        fut: Box::pin(inner.finalize()),
                    }
                } else if let Some((ctx, tls_transcript)) = inner.output.take() {
                    let transcript = tls_transcript
                        .to_transcript()
                        .expect("transcript is complete");

                    let (_, vm) = Arc::into_inner(inner.vm)
                        .expect("vm should have only 1 reference")
                        .into_inner()
                        .into_inner();

                    new = ClientState::Finished {
                        output: TlsOutput {
                            mux_fut: inner.mux,
                            ctx,
                            vm,
                            keys: inner.keys,
                            tls_transcript,
                            transcript,
                        },
                    };
                    out = Poll::Ready(Ok(()));
                } else {
                    new = ClientState::Running {
                        fut: Box::pin(inner.run()),
                    };
                }
            }
            ClientStateProj::Finished { .. } => {
                panic!("tls client future polled again after completion")
            }
            _ => (),
        };

        self.as_mut().project_replace(new);
        out
    }
}

struct InnerState {
    span: Span,
    mpc_ctrl: LeaderCtrl,
    tls: Pin<TlsFuture>,
    mpc: Pin<MpcFuture>,
    mux: MuxFuture,
    keys: SessionKeys,
    vm: Arc<Mutex<Deap<Mpc, Zk>>>,

    close: bool,
    output: Option<(Context, TlsTranscript)>,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn run(mut self) -> Result<Self, ProverError> {
        let mpc_ctrl = self.mpc_ctrl.clone();

        info!("starting MPC-TLS");

        futures::select! {
            tls_finish = &mut self.tls => {
                let _ = tls_finish?;
                if self.close {
                    mpc_ctrl.stop().await?;
                }
        },
            mux_finish = &mut self.mux => {
                if let Err(e) = mux_finish {
                    error!("mux error: {:?}", e);
                }
        },
            output = &mut self.mpc => {
                info!("finished MPC-TLS");
                self.output = Some(output?);
                },
        };

        Ok(self)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn finalize(mut self) -> Result<Self, ProverError> {
        let (ctx, transcript) = self
            .output
            .as_mut()
            .expect("output of MPC-TLS should be available");

        {
            let mut vm = self.vm.try_lock().expect("VM should not be locked");

            debug!("finalizing mpc");

            // Finalize DEAP.
            self.mux
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

            self.mux
                .poll_with(zk.execute_all(ctx).map_err(ProverError::zk))
                .await?;
        }

        Ok(self)
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
