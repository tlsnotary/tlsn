//! Prover.

mod client;
mod config;
mod error;
mod prove;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, TlsConfig, TlsConfigBuilder};
pub use error::ProverError;
use rustls_pki_types::CertificateDer;
pub use tlsn_core::{
    ProveConfig, ProveConfigBuilder, ProveConfigBuilderError, ProveRequest, ProverOutput,
};

use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_zk::ProverConfig as ZkProverConfig;
use std::task::Context;
use webpki::anchor_from_trusted_cert;

use crate::{
    Role,
    context::build_mt_context,
    msg::{Response, SetupRequest},
    mux::attach_mux,
    prover::client::{MpcControl, MpcTlsClient, TlsOutput},
};

use futures::{AsyncRead, AsyncWrite, FutureExt, TryFutureExt};
use mpc_tls::{MpcTlsLeader, SessionKeys};
use rand::Rng;
use serio::{SinkExt, stream::IoStreamExt};
use std::{sync::Arc, task::Poll};
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tlsn_core::{
    connection::{HandshakeData, ServerName},
    transcript::{TlsTranscript, Transcript},
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
            .poll_with(async {
                ctx.io_mut()
                    .send(SetupRequest {
                        config: self.config.protocol_config().clone(),
                        version: crate::config::VERSION.clone(),
                    })
                    .await?;

                ctx.io_mut()
                    .expect_next::<Response>()
                    .await?
                    .result
                    .map_err(ProverError::from)
            })
            .await?;

        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock)?;
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
                keys,
                vm,
            },
        })
    }
}

impl Prover<state::Setup> {
    /// Connects the prover.
    ///
    /// Returns a [`ProverControl`] and the connected prover.
    ///   - The prover control offers MPC-specific connection handling.
    ///   - The connected prover can be used to read and write from/to the active TLS connection.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect(self) -> Result<(MpcControl, Prover<state::Connected>), ProverError> {
        let state::Setup {
            mux_ctrl,
            mux_fut,
            mpc_tls,
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

        let span = self.span.clone();
        let ctrl = MpcControl {
            mpc_ctrl: mpc_ctrl.clone(),
        };

        let mpc_tls = MpcTlsClient::new(
            span,
            mpc_ctrl,
            client,
            mux_fut,
            Box::new(mpc_fut.map_err(ProverError::from).fuse()),
            keys,
            vm,
        );

        let prover = Prover::<state::Connected> {
            config: self.config,
            span: self.span,
            state: state::Connected {
                mux_ctrl,
                tls_client: Box::new(mpc_tls),
            },
        };
        Ok((ctrl, prover))
    }
}

impl Prover<state::Connected> {
    /// Returns `true` if the prover can read TLS data from the server.
    pub fn can_read_tls(&self) -> bool {
        self.state.tls_client.can_read_tls()
    }

    /// Returns `true` if the prover wants to write TLS data to the server.
    pub fn wants_write_tls(&self) -> bool {
        self.state.tls_client.wants_write_tls()
    }

    /// Reads TLS data from the server.
    pub fn read_tls(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.state.tls_client.read_tls(buf)
    }

    /// Writes TLS data for the server into the provided buffer.
    pub fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.state.tls_client.write_tls(buf)
    }

    /// Returns `true` if the prover can read plaintext data.
    pub fn can_read(&self) -> bool {
        self.state.tls_client.can_read()
    }

    /// Returns `true` if the prover wants to write plaintext data.
    pub fn wants_write(&self) -> bool {
        self.state.tls_client.wants_write()
    }

    /// Reads plaintext data from the server into the provided buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.state.tls_client.read(buf)
    }

    /// Writes plaintext data to be sent to the server.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.state.tls_client.write(buf)
    }

    /// Closes the server connection.
    pub fn close(&mut self) -> Result<(), std::io::Error> {
        self.state.tls_client.close()
    }

    /// Polls the prover to make progress. Returns a committed prover.
    pub fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Prover<state::Committed>, ProverError>> {
        let Poll::Ready(_) = self.state.tls_client.poll(cx)? else {
            return Poll::Pending;
        };

        let TlsOutput {
            mux_fut,
            ctx,
            vm,
            keys,
            tls_transcript,
            transcript,
        } = self
            .state
            .tls_client
            .into_output()
            .expect("tls output should be available");

        let prover = Prover::<state::Committed> {
            config: self.config.clone(),
            span: self.span.clone(),
            state: state::Committed {
                mux_ctrl: self.state.mux_ctrl.clone(),
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
                transcript,
            },
        };

        Poll::Ready(Ok(prover))
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
            keys,
            tls_transcript,
            transcript,
            ..
        } = &mut self.state;

        let request = ProveRequest {
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
            transcript: config
                .reveal()
                .map(|(sent, recv)| transcript.to_partial(sent.clone(), recv.clone())),
            transcript_commit: config.transcript_commit().map(|config| config.to_request()),
        };

        let output = mux_fut
            .poll_with(async {
                ctx.io_mut()
                    .send(request)
                    .await
                    .map_err(ProverError::from)?;

                ctx.io_mut().expect_next::<Response>().await?.result?;

                prove::prove(ctx, vm, keys, transcript, tls_transcript, config).await
            })
            .await?;

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

fn build_mpc_tls(
    config: &ProverConfig,
    ctx: mpz_common::Context,
) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsLeader) {
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
