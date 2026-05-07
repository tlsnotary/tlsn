use hmac_sha256::{MSMode, NetworkMode, Prf, PrfConfig};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::{Context, ThreadId};
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use std::sync::Arc;
use tlsn_core::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    Error,
    deps::{build_mpc_tls_config, translate_keys},
    proxy::ProxyVerifier,
};

cfg_select! {
    tlsn_insecure => {
        pub(crate) type VerifierMpc = mpz_ideal_vm::IdealVm;
        pub(crate) type VerifierZk = mpz_ideal_vm::IdealVm;
    }
    _ => {
        use mpz_garble::protocol::semihonest::Evaluator;
        use mpz_ot::cot::DerandCOTReceiver;
        use mpz_zk::Verifier;

        pub(crate) type VerifierMpc =
            Evaluator<DerandCOTReceiver<SharedRCOTReceiver<kos::Receiver<co::Sender>, bool, Block>>>;
        pub(crate) type VerifierZk =
            Verifier<SharedRCOTSender<ferret::Sender<kos::Sender<co::Receiver>>, Block>>;
    }
}

/// Protocol dependencies for Mpc.
pub(crate) struct VerifierMpcDeps {
    pub(crate) vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
    pub(crate) mpc_tls: Box<MpcTlsFollower>,
    pub(crate) keys: Option<SessionKeys>,
}

impl std::fmt::Debug for VerifierMpcDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierMpcDeps").finish_non_exhaustive()
    }
}

impl VerifierMpcDeps {
    pub(crate) fn new(config: &MpcTlsConfig, ctx: Context) -> Self {
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

        let mpc = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => { VerifierMpc::new(DerandCOTReceiver::new(rcot_recv.clone())) }
        };

        let zk = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => { VerifierZk::new(Default::default(), delta, rcot_send.clone()) }
        };

        let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Follower, mpc, zk)));
        let mpc_tls = MpcTlsFollower::new(
            build_mpc_tls_config(config),
            ctx,
            vm.clone(),
            rcot_send,
            (rcot_recv.clone(), rcot_recv.clone(), rcot_recv),
        );

        Self {
            vm,
            mpc_tls: Box::new(mpc_tls),
            keys: None,
        }
    }

    pub(crate) async fn setup(&mut self) -> Result<(), Error> {
        let mut keys = self.mpc_tls.alloc().map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed to allocate mpc-tls resources")
                .with_source(e)
        })?;
        let vm_lock = self.vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        self.keys = Some(keys);

        drop(vm_lock);

        debug!("setting up mpc-tls");
        self.mpc_tls.preprocess().await.map_err(|e| {
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

impl std::fmt::Debug for VerifierProxyDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierProxyDeps").finish_non_exhaustive()
    }
}

impl VerifierProxyDeps {
    pub(crate) fn new(_config: &ProxyTlsConfig, ctx: Context) -> Self {
        let vm = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => {{
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
                VerifierZk::new(Default::default(), delta, rcot_send)
            }}
        };

        let prf_config = PrfConfig::new(NetworkMode::Normal, MSMode::Direct);
        let prf = Prf::new(prf_config);

        let id = ctx.id().to_owned();
        let verifier = ProxyVerifier::new(prf, vm, ctx);

        Self {
            verifier: Box::new(verifier),
            id,
        }
    }

    pub(crate) async fn setup(&mut self) -> Result<(), Error> {
        self.verifier.alloc()?;

        debug!("setting up proxy-tls");
        self.verifier.preprocess().await?;

        Ok(())
    }
}
