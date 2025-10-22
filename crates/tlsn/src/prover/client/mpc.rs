//! Implementation of an MPC-TLS client.

use crate::{
    mux::MuxFuture,
    prover::{Mpc, ProverError, Zk, client::TlsClient},
    tag::verify_tags,
};
use futures::{Future, TryFutureExt};
use mpc_tls::{LeaderCtrl, SessionKeys};
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Execute, Vm};
use std::{pin::Pin, sync::Arc, task::Poll};
use tls_client::ClientConnection;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Instrument, Span, debug, info, instrument};

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
        vm: Arc<Mutex<Deap<Mpc, Zk>>>,
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
    Processing(
        Pin<
            Box<
                dyn Future<Output = Result<InnerClient, ProverError>>
                    + Send
                    + Sync
                    + Unpin
                    + 'static,
            >,
        >,
    ),
}

struct InnerClient {
    span: Span,
    mpc_ctrl: LeaderCtrl,
    tls: ClientConnection,
    mux: MuxFuture,
    keys: SessionKeys,
    mpc: Pin<MpcFuture>,
    vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

impl InnerClient {
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

        let (_, (mut ctx, tls_transcript)) = futures::try_join!(
            conn_fut,
            self.mpc.in_current_span().map_err(ProverError::from)
        )?;

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
        }

        // Pull out ZK VM.
        let (_, mut vm) = Arc::into_inner(self.vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();

        // Prove tag verification of received records.
        // The prover drops the proof output.
        let _ = verify_tags(
            &mut vm,
            (self.keys.server_write_key, self.keys.server_write_iv),
            self.keys.server_write_mac_key,
            *tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(ProverError::zk)?;

        self.mux
            .poll_with(vm.execute_all(&mut ctx).map_err(ProverError::zk))
            .await?;

        let transcript = tls_transcript
            .to_transcript()
            .expect("transcript is complete");

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
