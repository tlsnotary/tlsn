//! Implementation of an MPC-TLS client.

use crate::{
    mux::MuxFuture,
    prover::{ProverError, client::TlsClient},
};
use futures::Future;
use mpc_tls::{LeaderCtrl, SessionKeys};
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use std::{pin::Pin, sync::Arc, task::Poll};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tokio::sync::Mutex;
use tracing::{debug, info};

pub(crate) type MpcFuture =
    Box<dyn Future<Output = Result<(mpz_common::Context, TlsTranscript), ProverError>>>;

pub(crate) struct MpcTlsClient {
    tls: ClientState,
}

impl MpcTlsClient {
    pub(crate) fn new(
        tls: ClientConnection,
        mux: MuxFuture,
        mpc: MpcFuture,
        keys: SessionKeys,
        vm: Arc<Mutex<dyn Vm<Binary>>>,
    ) -> Self {
        Self {
            tls: ClientState::Idle(InnerClient {
                tls,
                mux,
                mpc: Box::into_pin(mpc),
                keys,
                vm,
            }),
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
        todo!()
    }

    fn poll(&mut self, cx: &mut std::task::Context) -> Poll<Result<TlsTranscript, ProverError>> {
        todo!()
    }
}

enum ClientState {
    Idle(InnerClient),
    Processing(Pin<Box<dyn Future<Output = InnerClient>>>),
}

struct InnerClient {
    tls: ClientConnection,
    mux: MuxFuture,
    keys: SessionKeys,
    mpc: Pin<MpcFuture>,
    vm: Arc<Mutex<dyn Vm<Binary>>>,
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

pub(crate) fn build_mpc_tls_client() {
    let fut = Box::pin({
        let span = self.span.clone();
        let mpc_ctrl = mpc_ctrl.clone();
        async move {
            let conn_fut = async {
                mux_fut
                    .poll_with(conn_fut.map_err(ProverError::from))
                    .await?;

                mpc_ctrl.stop().await?;

                Ok::<_, ProverError>(())
            };

            info!("starting MPC-TLS");

            let (_, (mut ctx, tls_transcript)) = futures::try_join!(
                conn_fut,
                mpc_fut.in_current_span().map_err(ProverError::from)
            )?;

            info!("finished MPC-TLS");

            {
                let mut vm = vm.try_lock().expect("VM should not be locked");

                debug!("finalizing mpc");

                // Finalize DEAP.
                mux_fut
                    .poll_with(vm.finalize(&mut ctx))
                    .await
                    .map_err(ProverError::mpc)?;

                debug!("mpc finalized");
            }

            // Pull out ZK VM.
            let (_, mut vm) = Arc::into_inner(vm)
                .expect("vm should have only 1 reference")
                .into_inner()
                .into_inner();

            // Prove tag verification of received records.
            // The prover drops the proof output.
            let _ = verify_tags(
                &mut vm,
                (keys.server_write_key, keys.server_write_iv),
                keys.server_write_mac_key,
                *tls_transcript.version(),
                tls_transcript.recv().to_vec(),
            )
            .map_err(ProverError::zk)?;

            mux_fut
                .poll_with(vm.execute_all(&mut ctx).map_err(ProverError::zk))
                .await?;

            let transcript = tls_transcript
                .to_transcript()
                .expect("transcript is complete");

            Ok(Prover {
                config: self.config,
                span: self.span,
                state: state::Committed {
                    mux_ctrl,
                    mux_fut,
                    ctx,
                    vm,
                    keys,
                    tls_transcript,
                    transcript,
                },
            })
        }
        .instrument(span)
    });
}
