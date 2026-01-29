use std::sync::Arc;

use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
#[cfg(not(tlsn_insecure))]
use mpz_garble::protocol::semihonest::Evaluator;
use mpz_garble_core::Delta;
#[cfg(not(tlsn_insecure))]
use mpz_ot::cot::DerandCOTReceiver;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use mpz_zk::Verifier;
#[cfg(not(tlsn_insecure))]
use tlsn_core::config::tls_commit::mpc::MpcTlsConfig;
use tlsn_core::config::tls_commit::{TlsCommitProtocolConfig, proxy::ProxyTlsConfig};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    Error,
    deps::{build_mpc_tls_config, translate_keys},
};

#[cfg(not(tlsn_insecure))]
pub(crate) type VerifierMpc =
    Evaluator<DerandCOTReceiver<SharedRCOTReceiver<kos::Receiver<co::Sender>, bool, Block>>>;
#[cfg(tlsn_insecure)]
pub(crate) type VerifierMpc = mpz_ideal_vm::IdealVm;

#[cfg(not(tlsn_insecure))]
pub(crate) type VerifierZk =
    Verifier<SharedRCOTSender<ferret::Sender<kos::Sender<co::Receiver>>, Block>>;
#[cfg(tlsn_insecure)]
pub(crate) type VerifierZk = mpz_ideal_vm::IdealVm;

pub(crate) enum VerifierDeps {
    Mpc {
        vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
        mpc_tls: Box<MpcTlsFollower>,
        keys: Option<SessionKeys>,
    },
    Proxy {
        vm: VerifierZk,
        keys: Option<SessionKeys>,
    },
}

impl VerifierDeps {
    pub(crate) fn new(config: &TlsCommitProtocolConfig, ctx: Context) -> Self {
        match config {
            TlsCommitProtocolConfig::Mpc(mpc_tls_config) => {
                build_mpc_verifier_deps(mpc_tls_config, ctx)
            }
            TlsCommitProtocolConfig::Proxy(proxy_tls_config) => {
                build_proxy_verifier_deps(proxy_tls_config, ctx)
            }
            _ => panic!("tls commitment mode not supported"),
        }
    }

    pub(crate) async fn setup(&mut self) -> Result<(), Error> {
        match self {
            VerifierDeps::Mpc {
                vm,
                mpc_tls,
                keys: verifier_keys,
            } => {
                let mut keys = mpc_tls.alloc().map_err(|e| {
                    Error::internal()
                        .with_msg("commitment protocol failed to allocate mpc-tls resources")
                        .with_source(e)
                })?;
                let vm_lock = vm.try_lock().expect("VM is not locked");
                translate_keys(&mut keys, &vm_lock);
                *verifier_keys = Some(keys);

                drop(vm_lock);

                debug!("setting up mpc-tls");
                mpc_tls.preprocess().await.map_err(|e| {
                    Error::internal()
                        .with_msg("commitment protocol failed during mpc-tls preprocessing")
                        .with_source(e)
                })?;

                Ok(())
            }
            VerifierDeps::Proxy { .. } => {
                todo!()
            }
        }
    }
}

fn build_mpc_verifier_deps(config: &MpcTlsConfig, ctx: Context) -> VerifierDeps {
    let mut rng = rand::rng();

    let delta = Delta::random(&mut rng);
    let base_ot_send = co::Sender::default();
    let base_ot_recv = co::Receiver::default();
    let rcot_send = kos::Sender::new(
        kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );
    let rcot_send = ferret::Sender::new(
        ferret::FerretConfig::builder()
            .lpn_type(ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        Block::random(&mut rng),
        rcot_send,
    );
    let rcot_recv = kos::Receiver::new(kos::ReceiverConfig::default(), base_ot_send);

    let rcot_send = SharedRCOTSender::new(rcot_send);
    let rcot_recv = SharedRCOTReceiver::new(rcot_recv);

    #[cfg(not(tlsn_insecure))]
    let mpc = VerifierMpc::new(DerandCOTReceiver::new(rcot_recv.clone()));
    #[cfg(tlsn_insecure)]
    let mpc = mpz_ideal_vm::IdealVm::new();

    #[cfg(not(tlsn_insecure))]
    let zk = VerifierZk::new(Default::default(), delta, rcot_send.clone());
    #[cfg(tlsn_insecure)]
    let zk = mpz_ideal_vm::IdealVm::new();

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Follower, mpc, zk)));
    let mpc_tls = MpcTlsFollower::new(
        build_mpc_tls_config(config),
        ctx,
        vm.clone(),
        rcot_send,
        (rcot_recv.clone(), rcot_recv.clone(), rcot_recv),
    );

    VerifierDeps::Mpc {
        vm,
        mpc_tls: Box::new(mpc_tls),
        keys: None,
    }
}

fn build_proxy_verifier_deps(config: &ProxyTlsConfig, ctx: Context) -> VerifierDeps {
    todo!()
}
