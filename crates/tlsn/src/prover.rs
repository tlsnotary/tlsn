//! Prover.

mod config;
mod error;
mod future;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, TlsConfig, TlsConfigBuilder};
pub use error::ProverError;
pub use future::ProverFuture;
pub use tlsn_core::{ProveConfig, ProveConfigBuilder, ProveConfigBuilderError, ProverOutput};

use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;

use crate::{
    Role,
    commit::{
        commit_records,
        hash::prove_hash,
        transcript::{TranscriptRefs, decode_transcript},
    },
    context::build_mt_context,
    encoding,
    mux::attach_mux,
    tag::verify_tags,
    zk_aes_ctr::ZkAesCtr,
};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsLeader, SessionKeys};
use rand::Rng;
use serio::{SinkExt, stream::IoStreamExt};
use std::{pin::Pin, sync::Arc};
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{TlsConnection, bind_client};
use tls_core::msgs::enums::ContentType;
use tlsn_attestation::{
    Attestation, CryptoProvider, Secrets,
    request::{Request, RequestConfig},
};
use tlsn_core::{
    ProvePayload,
    connection::ServerCertData,
    hash::{Blake3, HashAlgId, HashAlgorithm, Keccak256, Sha256},
    transcript::{Direction, TlsTranscript, Transcript, TranscriptCommitment, TranscriptSecret},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use tracing::{Instrument, Span, debug, info, info_span, instrument};

pub(crate) type RCOTSender = mpz_ot::rcot::shared::SharedRCOTSender<
    mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>,
    mpz_core::Block,
>;
pub(crate) type RCOTReceiver = mpz_ot::ferret::Receiver<
    mpz_ot::rcot::shared::SharedRCOTReceiver<
        mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>,
        bool,
        mpz_core::Block,
    >,
>;
pub(crate) type Mpc =
    mpz_garble::protocol::semihonest::Garbler<mpz_ot::cot::DerandCOTSender<RCOTSender>>;
pub(crate) type Zk = mpz_zk::Prover<RCOTReceiver>;

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
        // A context for preprocessing.
        let prepr_ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Sends protocol configuration to verifier for compatibility check.
        mux_fut
            .poll_with(ctx.io_mut().send(self.config.protocol_config().clone()))
            .await?;

        let (vm, mut mpc_tls, prepr_fut) = build_mpc_tls(&self.config, ctx, prepr_ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let mut vm_lock = vm.try_lock().expect("VM is not locked");
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

        debug!("setting up mpc-tls");
        // Changing the VM mode and setting a preprocessing future to have
        // concurrent ZK VM preprocessing and MPC-TLS execution.
        vm_lock.limited();
        mux_fut.aux(prepr_fut);
        drop(vm_lock);

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
            mut zk_aes_ctr_sent,
            mut zk_aes_ctr_recv,
            keys,
            vm,
            ..
        } = self.state;

        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let server_name =
            TlsServerName::try_from(self.config.server_name().as_str()).map_err(|_| {
                ProverError::config(format!(
                    "invalid server name: {}",
                    self.config.server_name()
                ))
            })?;

        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.tls_config().root_store().clone());

        let config = if let Some((cert, key)) = self.config.tls_config().client_auth() {
            config
                .with_single_cert(cert.clone(), key.clone())
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

                // Only finalize once the ZK VM preprocessing future is
                // complete.
                mux_fut.await_aux().await.map_err(ProverError::zk)?;

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
    pub async fn prove(&mut self, config: &ProveConfig) -> Result<ProverOutput, ProverError> {
        let state::Committed {
            mux_fut,
            ctx,
            vm,
            tls_transcript,
            transcript_refs,
            ..
        } = &mut self.state;

        let mut output = ProverOutput {
            transcript_commitments: Vec::new(),
            transcript_secrets: Vec::new(),
        };

        let payload = ProvePayload {
            server_identity: config.server_identity().then(|| {
                (
                    self.config.server_name().clone(),
                    ServerCertData {
                        certs: tls_transcript
                            .server_cert_chain()
                            .expect("server cert chain is present")
                            .to_vec(),
                        sig: tls_transcript
                            .server_signature()
                            .expect("server signature is present")
                            .clone(),
                        handshake: tls_transcript.handshake_data().clone(),
                    },
                )
            }),
            transcript: config.transcript().cloned(),
            transcript_commit: config.transcript_commit().map(|config| config.to_request()),
        };

        // Send payload.
        mux_fut
            .poll_with(ctx.io_mut().send(payload).map_err(ProverError::from))
            .await?;

        if let Some(partial_transcript) = config.transcript() {
            decode_transcript(
                vm,
                partial_transcript.sent_authed(),
                partial_transcript.received_authed(),
                transcript_refs,
            )
            .map_err(ProverError::zk)?;
        }

        let mut hash_commitments = None;
        if let Some(commit_config) = config.transcript_commit() {
            if commit_config.has_encoding() {
                let hasher: &(dyn HashAlgorithm + Send + Sync) =
                    match *commit_config.encoding_hash_alg() {
                        HashAlgId::SHA256 => &Sha256::default(),
                        HashAlgId::KECCAK256 => &Keccak256::default(),
                        HashAlgId::BLAKE3 => &Blake3::default(),
                        alg => {
                            return Err(ProverError::config(format!(
                                "unsupported hash algorithm for encoding commitment: {alg}"
                            )));
                        }
                    };

                let (commitment, tree) = mux_fut
                    .poll_with(
                        encoding::receive(
                            ctx,
                            hasher,
                            transcript_refs,
                            |plaintext| vm.get_macs(plaintext).expect("reference is valid"),
                            commit_config.iter_encoding(),
                        )
                        .map_err(ProverError::commit),
                    )
                    .await?;

                output
                    .transcript_commitments
                    .push(TranscriptCommitment::Encoding(commitment));
                output
                    .transcript_secrets
                    .push(TranscriptSecret::Encoding(tree));
            }

            if commit_config.has_hash() {
                hash_commitments = Some(
                    prove_hash(
                        vm,
                        transcript_refs,
                        commit_config
                            .iter_hash()
                            .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg)),
                    )
                    .map_err(ProverError::commit)?,
                );
            }
        }

        mux_fut
            .poll_with(vm.execute_all(ctx).map_err(ProverError::zk))
            .await?;

        if let Some((hash_fut, hash_secrets)) = hash_commitments {
            let hash_commitments = hash_fut.try_recv().map_err(ProverError::commit)?;
            for (commitment, secret) in hash_commitments.into_iter().zip(hash_secrets) {
                output
                    .transcript_commitments
                    .push(TranscriptCommitment::Hash(commitment));
                output
                    .transcript_secrets
                    .push(TranscriptSecret::Hash(secret));
            }
        }

        Ok(output)
    }

    /// Requests an attestation from the verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - The attestation request configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    #[deprecated(
        note = "attestation functionality will be removed from this API in future releases."
    )]
    pub async fn notarize(
        &mut self,
        config: &RequestConfig,
    ) -> Result<(Attestation, Secrets), ProverError> {
        #[allow(deprecated)]
        self.notarize_with_provider(config, &CryptoProvider::default())
            .await
    }

    /// Requests an attestation from the verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - The attestation request configuration.
    /// * `provider` - Cryptography provider.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    #[deprecated(
        note = "attestation functionality will be removed from this API in future releases."
    )]
    pub async fn notarize_with_provider(
        &mut self,
        config: &RequestConfig,
        provider: &CryptoProvider,
    ) -> Result<(Attestation, Secrets), ProverError> {
        let mut builder = ProveConfig::builder(self.transcript());

        if let Some(config) = config.transcript_commit() {
            // Temporarily, we reject attestation requests which contain hash commitments to
            // subsets of the transcript. We do this because we want to preserve the
            // obliviousness of the reference notary, and hash commitments currently leak
            // the ranges which are being committed.
            for ((direction, idx), _) in config.iter_hash() {
                let len = match direction {
                    Direction::Sent => self.transcript().sent().len(),
                    Direction::Received => self.transcript().received().len(),
                };

                if idx.start() > 0 || idx.end() < len || idx.count() != 1 {
                    return Err(ProverError::attestation(
                        "hash commitments to subsets of the transcript are currently not supported in attestation requests",
                    ));
                }
            }

            builder.transcript_commit(config.clone());
        }

        let disclosure_config = builder.build().map_err(ProverError::attestation)?;

        let ProverOutput {
            transcript_commitments,
            transcript_secrets,
            ..
        } = self.prove(&disclosure_config).await?;

        let state::Committed {
            mux_fut,
            ctx,
            tls_transcript,
            transcript,
            ..
        } = &mut self.state;

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(ServerCertData {
                certs: tls_transcript
                    .server_cert_chain()
                    .expect("server cert chain is present")
                    .to_vec(),
                sig: tls_transcript
                    .server_signature()
                    .expect("server signature is present")
                    .clone(),
                handshake: tls_transcript.handshake_data().clone(),
            })
            .transcript(transcript.clone())
            .transcript_commitments(transcript_secrets, transcript_commitments);

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let attestation = mux_fut
            .poll_with(async {
                debug!("sending attestation request");

                ctx.io_mut().send(request.clone()).await?;

                let attestation: Attestation = ctx.io_mut().expect_next().await?;

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
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

fn build_mpc_tls(
    config: &ProverConfig,
    ctx: Context,
    mut prepr_ctx: Context,
) -> (
    Arc<Mutex<Deap<Mpc, Zk>>>,
    MpcTlsLeader,
    Pin<Box<dyn Future<Output = Result<(), ProverError>> + Send>>,
) {
    let mut rng = rand::rng();
    let delta = Delta::new(Block::random(&mut rng));

    let base_ot_send = mpz_ot::chou_orlandi::Sender::default();
    let base_ot_recv = mpz_ot::chou_orlandi::Receiver::default();
    let rcot_send = mpz_ot::kos::Sender::new(
        mpz_ot::kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );

    let rcot_recv_kos =
        mpz_ot::kos::Receiver::new(mpz_ot::kos::ReceiverConfig::default(), base_ot_send);

    let rcot_recv_kos_shared = mpz_ot::rcot::shared::SharedRCOTReceiver::new(rcot_recv_kos);

    let rcot_recv_ferret = mpz_ot::ferret::Receiver::new(
        mpz_ot::ferret::FerretConfig::builder()
            .lpn_type(mpz_ot::ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        Block::random(&mut rng),
        rcot_recv_kos_shared.clone(),
    );
    let rcot_send = mpz_ot::rcot::shared::SharedRCOTSender::new(rcot_send);

    let mpc = Mpc::new(
        mpz_ot::cot::DerandCOTSender::new(rcot_send.clone()),
        rng.random(),
        delta,
    );

    let zk = Zk::new(rcot_recv_ferret);
    let zk_prover_ot = zk.ot();

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Leader, mpc, zk)));

    // A preprocessing future which will be run concurrently with MPC-TLS.
    // TODO: does this have to be pin ?
    let prepr_fut = Box::pin(async move {
        zk_prover_ot
            .try_lock()
            .expect("OT is not locked")
            .flush(&mut prepr_ctx)
            .await
            .map_err(|e| ProverError::zk(e))
    });

    (
        vm.clone(),
        MpcTlsLeader::new(
            config.build_mpc_tls_config(),
            ctx,
            vm,
            (rcot_send.clone(), rcot_send.clone(), rcot_send),
            // To minimize latency, the small amount of received OTs needed by
            // MPC-TLS will be provided by KOS rather than Ferret.
            rcot_recv_kos_shared,
        ),
        prepr_fut,
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
