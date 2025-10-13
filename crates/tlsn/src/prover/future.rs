//! This module collects futures which are used by the [Prover].

use crate::{
    commit::{commit_records, transcript::TranscriptRefs},
    mux::MuxFuture,
    prover::{
        Mpc, Prover, ProverConfig, ProverControl, ProverError, Zk, client::ConnectionFuture, state,
    },
    tag::verify_tags,
    zk_aes_ctr::ZkAesCtr,
};
use futures::{Future, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsError, SessionKeys};
use mpz_common::Context;
use mpz_vm_core::Execute;
use std::{pin::Pin, sync::Arc};
use tlsn_core::transcript::{ContentType, TlsTranscript};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Instrument, Span, debug, info};
use uid_mux::yamux::YamuxCtrl;

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture {
    #[allow(clippy::type_complexity)]
    pub(crate) fut: Pin<
        Box<dyn Future<Output = Result<Prover<state::Committed>, ProverError>> + Send + 'static>,
    >,
    pub(crate) ctrl: ProverControl,
}

impl ProverFuture {
    /// Returns a controller for the prover for advanced functionality.
    pub fn control(&self) -> ProverControl {
        self.ctrl.clone()
    }
}

impl Future for ProverFuture {
    type Output = Result<Prover<state::Committed>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

pub(crate) fn build_prover_fut(
    config: &ProverConfig,
    span: &Span,
    mux_ctrl: YamuxCtrl,
    mut mux_fut: MuxFuture,
    mpc_ctrl: &LeaderCtrl,
    mpc_fut: impl Future<Output = Result<(Context, TlsTranscript), MpcTlsError>> + Send + 'static,
    mut zk_aes_ctr_sent: ZkAesCtr,
    mut zk_aes_ctr_recv: ZkAesCtr,
    keys: SessionKeys,
    vm: Arc<Mutex<Deap<Mpc, Zk>>>,
    conn_fut: ConnectionFuture,
) -> Result<ProverFuture, ProverError> {
    let mpc_fut_ctrl = mpc_ctrl.clone();
    let span_fut = span.clone();
    let config_fut = config.clone();

    let fut = async move {
        let conn_fut = async {
            mux_fut
                .poll_with(conn_fut.map_err(ProverError::from))
                .await?;

            mpc_fut_ctrl.stop().await?;

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

        // Prove received plaintext. Prover drops the proof output, as
        // they trust themselves.
        let (sent_refs, _) = commit_records(
            &mut vm,
            &mut zk_aes_ctr_sent,
            tls_transcript
                .sent()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
        )
        .map_err(ProverError::zk)?;

        let (recv_refs, _) = commit_records(
            &mut vm,
            &mut zk_aes_ctr_recv,
            tls_transcript
                .recv()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
        )
        .map_err(ProverError::zk)?;

        mux_fut
            .poll_with(vm.execute_all(&mut ctx).map_err(ProverError::zk))
            .await?;

        let transcript = tls_transcript
            .to_transcript()
            .expect("transcript is complete");
        let transcript_refs = TranscriptRefs::new(sent_refs, recv_refs);

        Ok(Prover {
            config: config_fut,
            span: span_fut,
            state: state::Committed {
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                tls_transcript,
                transcript,
                transcript_refs,
            },
        })
    }
    .instrument(span.clone());

    let prover_fut = ProverFuture {
        fut: Box::pin(fut),
        ctrl: ProverControl::new(mpc_ctrl.clone()),
    };

    Ok(prover_fut)
}
