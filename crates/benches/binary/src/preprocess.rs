use hmac_sha256::{Config, MpcPrf};
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
use mpz_vm_core::memory::{binary::U8, correlated::Delta, Array, MemoryExt};
use rand::{rngs::StdRng, SeedableRng};

pub async fn preprocess_prf_circuits() {
    let (mut garbler, _) = mock_vm();
    let pms: Array<U8, 32> = garbler.alloc().unwrap();

    let mut prf = MpcPrf::new(Config::default());
    prf.alloc(&mut garbler, pms).unwrap();
}

fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

    let gen = Garbler::new(cot_send, [0u8; 16], delta);
    let ev = Evaluator::new(cot_recv);

    (gen, ev)
}
