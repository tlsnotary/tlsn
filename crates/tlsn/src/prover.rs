//! Prover.

mod client;
mod config;
mod conn;
mod control;
mod error;
mod future;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, TlsConfig, TlsConfigBuilder};
pub use conn::TlsConnection;
pub use control::ProverControl;
pub use error::ProverError;
pub use future::ProverFuture;
pub use tlsn_core::{ProveConfig, ProveConfigBuilder, ProveConfigBuilderError, ProverOutput};

use client::bind_client;
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;
use mpz_zk::ProverConfig as ZkProverConfig;

use crate::{
    Role,
    commit::{hash::prove_hash, transcript::decode_transcript},
    context::build_mt_context,
    encoding,
    mux::attach_mux,
    prover::{
        client::{bind_client_with, build_tls_client},
        future::build_prover_fut,
    },
    zk_aes_ctr::ZkAesCtr,
};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{MpcTlsLeader, SessionKeys};
use rand::Rng;
use serio::SinkExt;
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tlsn_core::{
    ProvePayload,
    connection::HandshakeData,
    hash::{Blake3, HashAlgId, HashAlgorithm, Keccak256, Sha256},
    transcript::{TlsTranscript, Transcript, TranscriptCommitment, TranscriptSecret},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, info_span, instrument};

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
    /// Returns a connection for reading and writing traffic from/to the server and a future that
    /// must be polled to drive the connection.
    pub async fn connect_with<S>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture), ProverError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let Prover {
            config,
            span,
            state:
                state::Setup {
                    mux_ctrl,
                    mux_fut,
                    mpc_tls,
                    zk_aes_ctr_sent,
                    zk_aes_ctr_recv,
                    keys,
                    vm,
                },
        } = self;

        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let client = build_tls_client(&config, &mpc_ctrl)?;
        let (client, conn_fut) = bind_client_with(socket, client);

        let tls_conn = TlsConnection::new(client);

        let prover_fut = build_prover_fut(
            &config,
            &span,
            mux_ctrl,
            mux_fut,
            &mpc_ctrl,
            mpc_fut,
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            keys,
            vm,
            conn_fut,
        )?;

        Ok((tls_conn, prover_fut))
    }

    /// Connects to the server.
    ///
    /// Returns a connected Prover and a future that must be polled to drive the connection.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn connect(self) -> Result<(Prover<state::Connected>, ProverFuture), ProverError> {
        let Prover {
            config,
            span,
            state:
                state::Setup {
                    mux_ctrl,
                    mux_fut,
                    mpc_tls,
                    zk_aes_ctr_sent,
                    zk_aes_ctr_recv,
                    keys,
                    vm,
                },
        } = self;

        let (mpc_ctrl, mpc_fut) = mpc_tls.run();
        let client = build_tls_client(&config, &mpc_ctrl)?;
        let (client_socket, server_socket, conn_fut) = bind_client(client);

        let prover_fut = build_prover_fut(
            &config,
            &span,
            mux_ctrl,
            mux_fut,
            &mpc_ctrl,
            mpc_fut,
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            keys,
            vm,
            conn_fut,
        )?;

        let prover = Prover {
            config,
            span,
            state: state::Connected {
                mpc_ctrl: mpc_ctrl.clone(),
                client_socket,
                server_socket,
            },
        };

        Ok((prover, prover_fut))
    }
}

impl Prover<state::Connected> {
    /// Returns `true` if the prover wants to write TLS data to the server.
    pub fn wants_write_tls(&self) -> bool {
        self.state.server_socket.wants_write()
    }

    /// Returns `true` if the prover wants to write plaintext data to the client.
    pub fn wants_write(&self) -> bool {
        self.state.client_socket.wants_write()
    }

    /// Reads TLS data from the server.
    pub fn read_tls(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.state.server_socket.write(buf)
    }

    /// Writes TLS data for the server into the provided buffer.
    pub fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.state.server_socket.read(buf)
    }

    /// Reads plaintext data from the server into the provided buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.state.client_socket.read(buf)
    }

    /// Writes plaintext data to be sent to the server.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.state.client_socket.write(buf)
    }

    /// Closes the server connection.
    pub fn close(&mut self) {
        self.state.server_socket.close();
    }

    /// Defers decryption of data from the server until the server has closed
    /// the connection.
    ///
    /// This is a performance optimization which will significantly reduce the
    /// amount of upload bandwidth used by the prover.
    ///
    /// # Notes
    ///
    /// The prover may need to close the connection to the server in order for
    /// it to close the connection on its end. If neither the prover or server
    /// close the connection this will cause a deadlock.
    pub async fn defer_decryption(&self) -> Result<(), ProverError> {
        self.state
            .mpc_ctrl
            .defer_decryption()
            .await
            .map_err(ProverError::from)
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
            transcript,
            transcript_refs,
            ..
        } = &mut self.state;

        let mut output = ProverOutput {
            transcript_commitments: Vec::new(),
            transcript_secrets: Vec::new(),
        };

        let partial_transcript = if let Some((sent, recv)) = config.reveal() {
            decode_transcript(vm, sent, recv, transcript_refs).map_err(ProverError::zk)?;

            Some(transcript.to_partial(sent.clone(), recv.clone()))
        } else {
            None
        };

        let payload = ProvePayload {
            handshake: config.server_identity().then(|| {
                (
                    self.config.server_name().clone(),
                    HandshakeData {
                        certs: tls_transcript
                            .server_cert_chain()
                            .expect("server cert chain is present")
                            .to_vec(),
                        sig: tls_transcript
                            .server_signature()
                            .expect("server signature is present")
                            .clone(),
                        binding: tls_transcript.certificate_binding().clone(),
                    },
                )
            }),
            transcript: partial_transcript,
            transcript_commit: config.transcript_commit().map(|config| config.to_request()),
        };

        // Send payload.
        mux_fut
            .poll_with(ctx.io_mut().send(payload).map_err(ProverError::from))
            .await?;

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
