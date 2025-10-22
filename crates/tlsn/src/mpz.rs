use std::sync::Arc;

use mpc_tls::{Config as MpcTlsConfig, MpcTlsFollower, MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
#[cfg(not(tlsn_insecure))]
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_garble_core::Delta;
use mpz_memory_core::{
    Vector,
    binary::U8,
    correlated::{Key, Mac},
};
#[cfg(not(tlsn_insecure))]
use mpz_ot::cot::{DerandCOTReceiver, DerandCOTSender};
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use mpz_zk::{Prover, Verifier};
#[cfg(not(tlsn_insecure))]
use rand::Rng;
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::transcript_internal::commit::encoding::{KeyStore, MacStore};

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

pub(crate) struct ProverDeps {
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    pub(crate) mpc_tls: MpcTlsLeader,
}

pub(crate) fn build_prover_deps(config: MpcTlsConfig, ctx: Context) -> ProverDeps {
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
        config,
        ctx,
        vm.clone(),
        (rcot_send.clone(), rcot_send.clone(), rcot_send),
        rcot_recv,
    );

    ProverDeps { vm, mpc_tls }
}

pub(crate) struct VerifierDeps {
    pub(crate) vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
    pub(crate) mpc_tls: MpcTlsFollower,
}

pub(crate) fn build_verifier_deps(config: MpcTlsConfig, ctx: Context) -> VerifierDeps {
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
        config,
        ctx,
        vm.clone(),
        rcot_send,
        (rcot_recv.clone(), rcot_recv.clone(), rcot_recv),
    );

    VerifierDeps { vm, mpc_tls }
}

pub(crate) fn translate_keys<Mpc, Zk>(keys: &mut SessionKeys, vm: &Deap<Mpc, Zk>) {
    keys.client_write_key = vm
        .translate(keys.client_write_key)
        .expect("VM memory should be consistent");
    keys.client_write_iv = vm
        .translate(keys.client_write_iv)
        .expect("VM memory should be consistent");
    keys.server_write_key = vm
        .translate(keys.server_write_key)
        .expect("VM memory should be consistent");
    keys.server_write_iv = vm
        .translate(keys.server_write_iv)
        .expect("VM memory should be consistent");
    keys.server_write_mac_key = vm
        .translate(keys.server_write_mac_key)
        .expect("VM memory should be consistent");
}

impl<T> KeyStore for Verifier<T> {
    fn delta(&self) -> &Delta {
        self.delta()
    }

    fn get_keys(&self, data: Vector<U8>) -> Option<&[Key]> {
        self.get_keys(data).ok()
    }
}

impl<T> MacStore for Prover<T> {
    fn get_macs(&self, data: Vector<U8>) -> Option<&[Mac]> {
        self.get_macs(data).ok()
    }
}

#[cfg(tlsn_insecure)]
mod insecure {
    use super::*;
    use mpz_ideal_vm::IdealVm;

    impl KeyStore for IdealVm {
        fn delta(&self) -> &Delta {
            unimplemented!("encodings not supported in insecure mode")
        }

        fn get_keys(&self, _data: Vector<U8>) -> Option<&[Key]> {
            unimplemented!("encodings not supported in insecure mode")
        }
    }

    impl MacStore for IdealVm {
        fn get_macs(&self, _data: Vector<U8>) -> Option<&[Mac]> {
            unimplemented!("encodings not supported in insecure mode")
        }
    }
}
