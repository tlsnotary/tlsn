use hmac_sha256::{MSMode, NetworkMode, Prf, PrfConfig};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::{Context, ThreadId};
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
use std::sync::Arc;
use tlsn_core::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    Error, Verify,
    deps::{ProtocolDeps, build_mpc_tls_config, translate_keys},
    proxy::ProxyVerifier,
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

/// Protocol dependencies for Mpc.
pub(crate) struct VerifierMpcDeps {
    pub(crate) vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
    pub(crate) mpc_tls: Box<MpcTlsFollower>,
    pub(crate) keys: Option<SessionKeys>,
}

impl ProtocolDeps<Verify> for MpcTlsConfig {
    type Deps = VerifierMpcDeps;

    fn to_deps(&self, ctx: Context) -> Self::Deps {
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
            build_mpc_tls_config(self),
            ctx,
            vm.clone(),
            rcot_send,
            (rcot_recv.clone(), rcot_recv.clone(), rcot_recv),
        );

        Self::Deps {
            vm,
            mpc_tls: Box::new(mpc_tls),
            keys: None,
        }
    }

    async fn setup(deps: &mut Self::Deps) -> Result<(), Error> {
        let mut keys = deps.mpc_tls.alloc().map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed to allocate mpc-tls resources")
                .with_source(e)
        })?;
        let vm_lock = deps.vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        deps.keys = Some(keys);

        drop(vm_lock);

        debug!("setting up mpc-tls");
        deps.mpc_tls.preprocess().await.map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed during mpc-tls preprocessing")
                .with_source(e)
        })?;

        Ok(())
    }
}

/// Protocol dependencies for Proxy.
pub(crate) struct VerifierProxyDeps {
    pub(crate) verifier: Box<ProxyVerifier>,
    pub(crate) id: ThreadId,
}

impl ProtocolDeps<Verify> for ProxyTlsConfig {
    type Deps = VerifierProxyDeps;

    fn to_deps(&self, ctx: Context) -> Self::Deps {
        let mut rng = rand::rng();
        let delta = Delta::random(&mut rng);

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
        let rcot_send = SharedRCOTSender::new(rcot_send);

        #[cfg(not(tlsn_insecure))]
        let vm = VerifierZk::new(Default::default(), delta, rcot_send.clone());
        #[cfg(tlsn_insecure)]
        let vm = mpz_ideal_vm::IdealVm::new();

        let prf_config = PrfConfig::new(NetworkMode::Normal, MSMode::Direct);
        let prf = Prf::new(prf_config);

        let id = ctx.id().to_owned();
        let verifier = ProxyVerifier::new(prf, vm, ctx);

        Self::Deps {
            verifier: Box::new(verifier),
            id,
        }
    }

    async fn setup(deps: &mut Self::Deps) -> Result<(), Error> {
        deps.verifier.alloc()?;

        debug!("setting up proxy-tls");
        deps.verifier.preprocess().await?;

        Ok(())
    }
}
