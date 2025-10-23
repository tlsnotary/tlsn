//! Implementation of an MPC-TLS client.

use crate::{
    mux::MuxFuture,
    prover::{Mpc, ProverError, Zk, client::TlsClient},
    tag::verify_tags,
};
use futures::{Future, FutureExt, TryFutureExt};
use mpc_tls::{LeaderCtrl, SessionKeys};
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Execute, Vm};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Poll, Waker},
};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Instrument, Span, debug, info, instrument};

pub(crate) type MpcFuture =
    Box<dyn Future<Output = Result<(mpz_common::Context, TlsTranscript), ProverError>>>;

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
                inner: InnerState {
                    span,
                    mpc_ctrl,
                    tls,
                    mux,
                    mpc: Box::into_pin(mpc),
                    keys,
                    vm,
                    close_mpc_tls: false,
                    transcript: None,
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
            inner: InnerState { close_mpc_tls, .. },
            ..
        } = &mut self.state
        {
            *close_mpc_tls = true;
            return Ok(());
        }
        Err(std::io::Error::other(
            "unable to close tls connection, poll again and retry to close",
        ))
    }

    fn poll(&mut self, cx: &mut std::task::Context) -> Poll<Result<TlsTranscript, ProverError>> {
        self.state.poll_unpin(cx)
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
        Processing {
            #[pin]
            fut: Pin<Box<dyn Future<Output = Result<InnerState, ProverError>>>>,
        },
        Finished,
        Error
    }
}

impl Future for ClientState {
    type Output = Result<TlsTranscript, ProverError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut out: Poll<Self::Output> = Poll::Pending;
        let mut new = Self::Error;

        let this = self.as_mut().project();
        match this {
            ClientStateProjRef::Processing { mut fut } => match fut.as_mut().poll(cx) {
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
            ClientStateProj::Idle { inner, .. } => {
                if let Some(transcript) = inner.transcript {
                    new = ClientState::Finished;
                    out = Poll::Ready(Ok(transcript));
                } else {
                    new = ClientState::Processing {
                        fut: Box::pin(inner.run()),
                    };
                }
            }
            ClientStateProj::Finished => {
                panic!("tls client future polled again after completion")
            }
            _ => (),
        };

        // We do not want to encounter `self` in `Processing` state, so we call poll again in this
        // case.
        let is_processing = matches!(new, ClientState::Processing { .. });
        self.as_mut().project_replace(new);

        if is_processing {
            return self.poll(cx);
        }

        out
    }
}

struct InnerState {
    span: Span,
    mpc_ctrl: LeaderCtrl,
    tls: ClientConnection,
    mux: MuxFuture,
    mpc: Pin<MpcFuture>,
    keys: SessionKeys,
    vm: Arc<Mutex<Deap<Mpc, Zk>>>,
    close_mpc_tls: bool,
    transcript: Option<TlsTranscript>,
}

impl InnerState {
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn run(mut self) -> Result<Self, ProverError> {
        let mpc_ctrl = self.mpc_ctrl.clone();

        let conn_fut = async {
            self.mux
                .poll_with(self.tls.process_new_packets().map_err(ProverError::from))
                .await?;

            mpc_ctrl.stop().await?;

            Ok::<_, ProverError>(())
        };

        info!("starting MPC-TLS");

        let mpc = &mut self.mpc;
        let (_, (mut ctx, tls_transcript)) = futures::try_join!(conn_fut, mpc)?;

        info!("finished MPC-TLS");

        {
            let mut vm = self.vm.try_lock().expect("VM should not be locked");

            debug!("finalizing mpc");

            // Finalize DEAP.
            self.mux
                .poll_with(vm.finalize(&mut ctx))
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
                *tls_transcript.version(),
                tls_transcript.recv().to_vec(),
            )
            .map_err(ProverError::zk)?;

            self.mux
                .poll_with(zk.execute_all(&mut ctx).map_err(ProverError::zk))
                .await?;
        }

        self.transcript = Some(tls_transcript);
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
