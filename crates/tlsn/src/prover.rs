//! Prover.

mod config;
mod error;
mod future;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, TlsConfig, TlsConfigBuilder};
pub use error::ProverError;
pub use future::ProverFuture;
pub use tlsn_core::{ProveConfig, ProveConfigBuilder, ProveConfigBuilderError, ProverOutput};

use crate::{
    EncodingMemory, Role,
    commit::{ENCODING_SIZE, ProvingState, TranscriptRefs},
    context::build_mt_context,
    mux::attach_mux,
    tag::verify_tags,
    zk_aes_ctr::ZkAesCtr,
};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_memory_core::{
    Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::prelude::*;
use mpz_zk::ProverConfig as ZkProverConfig;
use rand::Rng;
use rustls_pki_types::CertificateDer;
use serio::SinkExt;
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{TlsConnection, bind_client};
use tlsn_core::{
    ProvePayload,
    connection::{HandshakeData, ServerName},
    transcript::{TlsTranscript, Transcript},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Instrument, Span, debug, info, info_span, instrument};
use webpki::anchor_from_trusted_cert;

pub(crate) type RCOTSender = mpz_ot::rcot::shared::SharedRCOTSender<
    mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>,
    mpz_core::Block,
>;
pub(crate) type RCOTReceiver = mpz_ot::rcot::shared::SharedRCOTReceiver<
    mpz_ot::ferret::Receiver<mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>>,
    bool,
    mpz_core::Block,
>;
pub(crate) type Mpc =
    mpz_garble::protocol::semihonest::Garbler<mpz_ot::cot::DerandCOTSender<RCOTSender>>;
pub(crate) type Zk = mpz_zk::Prover<RCOTReceiver>;

impl<T> EncodingMemory<Binary> for mpz_zk::Prover<T> {
    fn get_encodings(&self, values: &[Vector<U8>]) -> Vec<u8> {
        let len = values.iter().map(|v| v.len()).sum::<usize>() * ENCODING_SIZE;
        let mut encodings = Vec::with_capacity(len);

        for &v in values {
            let macs = self.get_macs(v).expect("macs should be available");
            encodings.extend(macs.iter().flat_map(|mac| mac.as_bytes()));
        }
        encodings
    }
}

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: state::ProverState = state::Initialized> {
    config: ProverConfig,
    span: Span,
    state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    pub fn new(config: ProverConfig) -> Self {
        let span = info_span!("prover");
        Self {
            config,
            span,
            state: state::Initialized,
        }
    }

    /// Sets up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the TLS verifier.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Prover<state::Setup>, ProverError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Sends protocol configuration to verifier for compatibility check.
        mux_fut
            .poll_with(ctx.io_mut().send(self.config.protocol_config().clone()))
            .await?;

        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock)?;

        // Allocate for committing to plaintext.
        let mut zk_aes_ctr_sent = ZkAesCtr::new(Role::Prover);
        zk_aes_ctr_sent.set_key(keys.client_write_key, keys.client_write_iv);
        zk_aes_ctr_sent.alloc(
            &mut *vm_lock.zk(),
            self.config.protocol_config().max_sent_data(),
        )?;

        let mut zk_aes_ctr_recv = ZkAesCtr::new(Role::Prover);
        zk_aes_ctr_recv.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes_ctr_recv.alloc(
            &mut *vm_lock.zk(),
            self.config.protocol_config().max_recv_data(),
        )?;

        drop(vm_lock);

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                mpc_tls,
                zk_aes_ctr_sent,
                zk_aes_ctr_recv,
                keys,
                vm,
            },
        })
    }
}

impl Prover<state::Setup> {
    /// Connects to the server using the provided socket.
    ///
    /// Returns a handle to the TLS connection, a future which returns the
    /// prover once the connection is closed.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the server.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture), ProverError> {
        let state::Setup {
            mux_ctrl,
            mut mux_fut,
            mpc_tls,
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            keys,
            vm,
            ..
        } = self.state;

        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let ServerName::Dns(server_name) = self.config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");

        let root_store = if let Some(root_store) = self.config.tls_config().root_store() {
            let roots = root_store
                .roots
                .iter()
                .map(|cert| {
                    let der = CertificateDer::from_slice(&cert.0);
                    anchor_from_trusted_cert(&der)
                        .map(|anchor| anchor.to_owned())
                        .map_err(ProverError::config)
                })
                .collect::<Result<Vec<_>, _>>()?;
            tls_client::RootCertStore { roots }
        } else {
            tls_client::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }
        };

        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);

        let config = if let Some((cert, key)) = self.config.tls_config().client_auth() {
            config
                .with_single_cert(
                    cert.iter()
                        .map(|cert| tls_client::Certificate(cert.0.clone()))
                        .collect(),
                    tls_client::PrivateKey(key.0.clone()),
                )
                .map_err(ProverError::config)?
        } else {
            config.with_no_client_auth()
        };

        let client =
            ClientConnection::new(Arc::new(config), Box::new(mpc_ctrl.clone()), server_name)
                .map_err(ProverError::config)?;

        let (conn, conn_fut) = bind_client(socket, client);

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

                let (sent_len, recv_len) = transcript.len();
                let transcript_refs = TranscriptRefs::new(sent_len, recv_len);

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Committed {
                        mux_ctrl,
                        mux_fut,
                        ctx,
                        vm,
                        tls_transcript,
                        transcript,
                        transcript_refs,
                        zk_aes_ctr_sent,
                        zk_aes_ctr_recv,
                        keys,
                        encodings_transferred: false,
                    },
                })
            }
            .instrument(span)
        });

        Ok((
            conn,
            ProverFuture {
                fut,
                ctrl: ProverControl { mpc_ctrl },
            },
        ))
    }
}

impl Prover<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Proves information to the verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - The disclosure configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn prove(&mut self, config: ProveConfig) -> Result<ProverOutput, ProverError> {
        let state::Committed {
            mux_fut,
            ctx,
            vm,
            tls_transcript,
            transcript_refs,
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            keys,
            encodings_transferred,
            ..
        } = &mut self.state;

        // Create and send prove payload.
        let server_name = self.config.server_name();
        let handshake = config
            .server_identity()
            .then(|| (server_name.clone(), HandshakeData::new(tls_transcript)));
        let payload = ProvePayload::new(&config, handshake);

        mux_fut
            .poll_with(ctx.io_mut().send(payload).map_err(ProverError::from))
            .await?;

        let proving_state = ProvingState::for_prover(
            config,
            tls_transcript,
            transcript_refs,
            *encodings_transferred,
        );

        let (output, encodings_executed) = mux_fut
            .poll_with(
                proving_state
                    .prove(vm, ctx, zk_aes_ctr_sent, zk_aes_ctr_recv, *keys)
                    .map_err(ProverError::from),
            )
            .await?;

        *encodings_transferred = encodings_executed;
        Ok(output)
    }

    /// Closes the connection with the verifier.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<(), ProverError> {
        let state::Committed {
            mux_ctrl, mux_fut, ..
        } = self.state;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(())
    }
}

fn build_mpc_tls(config: &ProverConfig, ctx: Context) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsLeader) {
    let mut rng = rand::rng();
    let delta = Delta::new(Block::random(&mut rng));

    let base_ot_send = mpz_ot::chou_orlandi::Sender::default();
    let base_ot_recv = mpz_ot::chou_orlandi::Receiver::default();
    let rcot_send = mpz_ot::kos::Sender::new(
        mpz_ot::kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );
    let rcot_recv =
        mpz_ot::kos::Receiver::new(mpz_ot::kos::ReceiverConfig::default(), base_ot_send);
    let rcot_recv = mpz_ot::ferret::Receiver::new(
        mpz_ot::ferret::FerretConfig::builder()
            .lpn_type(mpz_ot::ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        Block::random(&mut rng),
        rcot_recv,
    );

    let rcot_send = mpz_ot::rcot::shared::SharedRCOTSender::new(rcot_send);
    let rcot_recv = mpz_ot::rcot::shared::SharedRCOTReceiver::new(rcot_recv);

    let mpc = Mpc::new(
        mpz_ot::cot::DerandCOTSender::new(rcot_send.clone()),
        rng.random(),
        delta,
    );

    let zk = Zk::new(ZkProverConfig::default(), rcot_recv.clone());

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Leader, mpc, zk)));

    (
        vm.clone(),
        MpcTlsLeader::new(
            config.build_mpc_tls_config(),
            ctx,
            vm,
            (rcot_send.clone(), rcot_send.clone(), rcot_send),
            rcot_recv,
        ),
    )
}

/// A controller for the prover.
#[derive(Clone)]
pub struct ProverControl {
    mpc_ctrl: LeaderCtrl,
}

impl ProverControl {
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

/// Translates VM references to the ZK address space.
fn translate_keys<Mpc, Zk>(keys: &mut SessionKeys, vm: &Deap<Mpc, Zk>) -> Result<(), ProverError> {
    keys.client_write_key = vm
        .translate(keys.client_write_key)
        .map_err(ProverError::mpc)?;
    keys.client_write_iv = vm
        .translate(keys.client_write_iv)
        .map_err(ProverError::mpc)?;
    keys.server_write_key = vm
        .translate(keys.server_write_key)
        .map_err(ProverError::mpc)?;
    keys.server_write_iv = vm
        .translate(keys.server_write_iv)
        .map_err(ProverError::mpc)?;
    keys.server_write_mac_key = vm
        .translate(keys.server_write_mac_key)
        .map_err(ProverError::mpc)?;

    Ok(())
}
