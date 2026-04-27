use mpc_tls::{MpcTlsLeader, SessionKeys};
use mpz_common::{Context, ThreadId};
use mpz_core::Block;
#[cfg(not(tlsn_insecure))]
use mpz_garble::protocol::semihonest::Garbler;
use mpz_garble_core::Delta;
#[cfg(not(tlsn_insecure))]
use mpz_ot::cot::DerandCOTSender;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use mpz_zk::Prover;
#[cfg(not(tlsn_insecure))]
use rand::Rng;
use std::sync::Arc;
use tlsn_core::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    Error,
    deps::{ProtocolDeps, build_mpc_tls_config, translate_keys},
    proxy::ProxyProver,
};

#[cfg(not(tlsn_insecure))]
pub(crate) type ProverMpc =
    Garbler<DerandCOTSender<SharedRCOTSender<kos::Sender<co::Receiver>, Block>>>;
#[cfg(tlsn_insecure)]
pub(crate) type ProverMpc = mpz_ideal_vm::IdealVm;

#[cfg(not(tlsn_insecure))]
pub(crate) type ProverZk =
    Prover<SharedRCOTReceiver<ferret::Receiver<kos::Receiver<co::Sender>>, bool, Block>>;
#[cfg(tlsn_insecure)]
pub(crate) type ProverZk = mpz_ideal_vm::IdealVm;

/// Protocol dependencies for MPC.
pub struct Mpc {
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    pub(crate) mpc_tls: Box<MpcTlsLeader>,
    pub(crate) keys: Option<SessionKeys>,
}

impl ProtocolDeps for Mpc {
    type Config = MpcTlsConfig;

    fn new(config: &MpcTlsConfig, ctx: Context) -> Self {
        let mut rng = rand::rng();
        let delta = Delta::new(Block::random(&mut rng));

        let base_ot_send = co::Sender::default();
        let base_ot_recv = co::Receiver::default();
        let rcot_send = kos::Sender::new(
            kos::SenderConfig::default(),
            delta.into_inner(),
            base_ot_recv,
        );
        let rcot_recv = kos::Receiver::new(kos::ReceiverConfig::default(), base_ot_send);
        let rcot_recv = ferret::Receiver::new(
            ferret::FerretConfig::builder()
                .lpn_type(ferret::LpnType::Regular)
                .build()
                .expect("ferret config is valid"),
            Block::random(&mut rng),
            rcot_recv,
        );

        let rcot_send = SharedRCOTSender::new(rcot_send);
        let rcot_recv = SharedRCOTReceiver::new(rcot_recv);

        #[cfg(not(tlsn_insecure))]
        let mpc = ProverMpc::new(DerandCOTSender::new(rcot_send.clone()), rng.random(), delta);
        #[cfg(tlsn_insecure)]
        let mpc = mpz_ideal_vm::IdealVm::new();

        #[cfg(not(tlsn_insecure))]
        let zk = ProverZk::new(Default::default(), rcot_recv.clone());
        #[cfg(tlsn_insecure)]
        let zk = mpz_ideal_vm::IdealVm::new();

        let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Leader, mpc, zk)));
        let mpc_tls = MpcTlsLeader::new(
            build_mpc_tls_config(config),
            ctx,
            vm.clone(),
            (rcot_send.clone(), rcot_send.clone(), rcot_send),
            rcot_recv,
        );

        Self {
            vm,
            mpc_tls: Box::new(mpc_tls),
            keys: None,
        }
    }

    async fn setup(&mut self) -> Result<(), Error> {
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
pub struct Proxy {
    pub(crate) prover: Box<ProxyProver>,
    pub(crate) id: ThreadId,
}

impl ProtocolDeps for Proxy {
    type Config = ProxyTlsConfig;

    fn new(_config: &ProxyTlsConfig, ctx: Context) -> Self {
        let mut rng = rand::rng();

        let base_ot_send = co::Sender::default();
        let rcot_recv = kos::Receiver::new(kos::ReceiverConfig::default(), base_ot_send);
        let rcot_recv = ferret::Receiver::new(
            ferret::FerretConfig::builder()
                .lpn_type(ferret::LpnType::Regular)
                .build()
                .expect("ferret config is valid"),
            Block::random(&mut rng),
            rcot_recv,
        );
        let rcot_recv = SharedRCOTReceiver::new(rcot_recv);

        #[cfg(not(tlsn_insecure))]
        let vm = ProverZk::new(Default::default(), rcot_recv.clone());
        #[cfg(tlsn_insecure)]
        let vm = mpz_ideal_vm::IdealVm::new();

        let id = ctx.id().to_owned();
        let prover = ProxyProver::new(vm, ctx);

        Self {
            prover: Box::new(prover),
            id,
        }
    }

    async fn setup(&mut self) -> Result<(), Error> {
        self.prover.alloc()?;

        debug!("setting up proxy-tls");
        self.prover.preprocess().await?;

        Ok(())
    }
}
