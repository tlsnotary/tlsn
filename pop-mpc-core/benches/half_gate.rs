use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pop_mpc_core::block::Block;
use pop_mpc_core::circuit::Circuit;
use pop_mpc_core::garble::{
    evaluator::HalfGateEvaluator, generator::half_gate::*, generator::GarbledCircuitGenerator,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("half_gate_garble_and", move |bench| {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let gen = HalfGateGenerator::new();

        let mut delta = Block::random(&mut rng);
        delta.set_lsb();
        let x_0 = Block::random(&mut rng);
        let x = [x_0, x_0 ^ delta];
        let y_0 = Block::random(&mut rng);
        let y = [y_0, y_0 ^ delta];
        let gid: usize = 1;

        bench.iter(|| {
            let res = gen.and_gate(&mut cipher, x, y, delta, gid);
            black_box(res);
        });
    });

    c.bench_function("half_gate_eval_and", move |bench| {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let gen = HalfGateGenerator::new();
        let ev = HalfGateEvaluator::new();

        let mut delta = Block::random(&mut rng);
        delta.set_lsb();
        let x_0 = Block::random(&mut rng);
        let x = [x_0, x_0 ^ delta];
        let y_0 = Block::random(&mut rng);
        let y = [y_0, y_0 ^ delta];
        let gid: usize = 1;

        let (_, table) = gen.and_gate(&mut cipher, x, y, delta, gid);

        bench.iter(|| {
            let res = ev.and_gate(&mut cipher, x[0], y[0], table, gid);
            black_box(res);
        });
    });

    c.bench_function("half_gate_aes", move |bench| {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let circ = Circuit::load("circuits/aes_128_reverse.bin").unwrap();
        let half_gate = HalfGateGenerator::new();
        bench.iter(|| {
            let gb = half_gate.garble(&mut cipher, &mut rng, &circ).unwrap();
            black_box(gb);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
