//! TLSNotary prover library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod future;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, ProverConfigBuilderError};
pub use error::ProverError;
pub use future::ProverFuture;
pub use tlsn_core::{ProveConfig, ProveConfigBuilder, ProveConfigBuilderError, ProverOutput};

use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsLeader, SessionKeys};
use rand::Rng;
use serio::{stream::IoStreamExt, SinkExt};
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, TlsConnection};
use tls_core::msgs::enums::ContentType;
use tlsn_common::{
    commit::{commit_records, hash::prove_hash},
    context::build_mt_context,
    encoding,
    mux::attach_mux,
    tag::verify_tags,
    transcript::{decode_transcript, Record, TlsTranscript},
    zk_aes_ctr::ZkAesCtr,
    Role,
};
use tlsn_core::{
    attestation::Attestation,
    connection::{
        ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerCertData, ServerSignature,
        TranscriptLength,
    },
    request::{Request, RequestConfig},
    transcript::{Direction, Transcript, TranscriptCommitment, TranscriptSecret},
    ProvePayload, Secrets,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use tracing::{debug, info, info_span, instrument, Instrument, Span};

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
        translate_keys(&mut keys, &vm.try_lock().expect("VM is not locked"))?;

        // Allocate for committing to plaintext.
        let mut zk_aes_ctr = ZkAesCtr::new(Role::Prover);
        zk_aes_ctr.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes_ctr.alloc(
            &mut (*vm.try_lock().expect("VM is not locked").zk()),
            self.config.protocol_config().max_recv_data(),
        )?;

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
                zk_aes_ctr,
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
            mut zk_aes_ctr,
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
            .with_root_certificates(self.config.crypto_provider().cert.root_store().clone())
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), Box::new(mpc_ctrl.clone()), server_name)
                .map_err(ProverError::config)?;

        let (conn, conn_fut) = bind_client(socket, client);

        let start_time = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();

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

                let (_, (mut ctx, mut data, ..)) = futures::try_join!(
                    conn_fut,
                    mpc_fut.in_current_span().map_err(ProverError::from)
                )?;

                info!("finished MPC-TLS");

                {
                    let mut vm = vm.try_lock().expect("VM should not be locked");

                    translate_transcript(&mut data.transcript, &vm)?;

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
                    (data.keys.server_write_key, data.keys.server_write_iv),
                    data.keys.server_write_mac_key,
                    data.transcript.recv.clone(),
                )
                .map_err(ProverError::zk)?;

                // Prove received plaintext. Prover drops the proof output, as
                // they trust themselves.
                _ = commit_records(
                    &mut vm,
                    &mut zk_aes_ctr,
                    data.transcript
                        .recv
                        .iter_mut()
                        .filter(|record| record.typ == ContentType::ApplicationData),
                )
                .map_err(ProverError::zk)?;

                mux_fut
                    .poll_with(vm.execute_all(&mut ctx).map_err(ProverError::zk))
                    .await?;

                let transcript = data
                    .transcript
                    .to_transcript()
                    .expect("transcript is complete");
                let transcript_refs = data
                    .transcript
                    .to_transcript_refs()
                    .expect("transcript is complete");

                let connection_info = ConnectionInfo {
                    time: start_time,
                    version: data
                        .protocol_version
                        .try_into()
                        .expect("only supported version should have been accepted"),
                    transcript_length: TranscriptLength {
                        sent: transcript.sent().len() as u32,
                        received: transcript.received().len() as u32,
                    },
                };

                let server_cert_data =
                    ServerCertData {
                        certs: data
                            .server_cert_details
                            .cert_chain()
                            .iter()
                            .cloned()
                            .map(|c| c.into())
                            .collect(),
                        sig: ServerSignature {
                            scheme: data.server_kx_details.kx_sig().scheme.try_into().expect(
                                "only supported signature scheme should have been accepted",
                            ),
                            sig: data.server_kx_details.kx_sig().sig.0.clone(),
                        },
                        handshake: HandshakeData::V1_2(HandshakeDataV1_2 {
                            client_random: data.client_random.0,
                            server_random: data.server_random.0,
                            server_ephemeral_key: data
                                .server_key
                                .try_into()
                                .expect("only supported key scheme should have been accepted"),
                        }),
                    };

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Committed {
                        mux_ctrl,
                        mux_fut,
                        ctx,
                        _keys: keys,
                        vm,
                        connection_info,
                        server_cert_data,
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
    /// Returns the connection information.
    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.state.connection_info
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
            server_cert_data,
            transcript_refs,
            ..
        } = &mut self.state;

        let mut output = ProverOutput {
            transcript_commitments: Vec::new(),
            transcript_secrets: Vec::new(),
        };

        let payload = ProvePayload {
            server_identity: config
                .server_identity()
                .then(|| (self.config.server_name().clone(), server_cert_data.clone())),
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
                let hasher = self
                    .config
                    .crypto_provider()
                    .hash
                    .get(commit_config.encoding_hash_alg())
                    .map_err(ProverError::config)?;

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
            server_cert_data,
            transcript,
            ..
        } = &mut self.state;

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data.clone())
            .transcript(transcript.clone())
            .transcript_commitments(transcript_secrets, transcript_commitments);

        let (request, secrets) = builder
            .build(self.config.crypto_provider())
            .map_err(ProverError::attestation)?;

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

    let zk = Zk::new(rcot_recv.clone());

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

/// Translates VM references to the ZK address space.
fn translate_transcript<Mpc, Zk>(
    transcript: &mut TlsTranscript,
    vm: &Deap<Mpc, Zk>,
) -> Result<(), ProverError> {
    for Record { plaintext_ref, .. } in transcript.sent.iter_mut().chain(transcript.recv.iter_mut())
    {
        if let Some(plaintext_ref) = plaintext_ref.as_mut() {
            *plaintext_ref = vm.translate(*plaintext_ref).map_err(ProverError::mpc)?;
        }
    }

    Ok(())
}
