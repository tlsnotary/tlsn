use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pop_mpc::circuit::Circuit;
use pop_mpc::garble::{
    evaluator::HalfGateEvaluator, generator::half_gate::*, generator::GarbledCircuitGenerator,
    hash::aes::Aes,
};
use pop_mpc::prg::{Prg, RandPrg};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("half_gate_garble_and", move |bench| {
        let mut prg = RandPrg::new();
        let h = Aes::new(&[0u8; 16]);
        let gen = HalfGateGenerator;

        let mut delta = prg.random_block();
        delta.set_lsb();
        let x_0 = prg.random_block();
        let x = [x_0, x_0 ^ delta];
        let y_0 = prg.random_block();
        let y = [y_0, y_0 ^ delta];
        let gid: usize = 1;

        bench.iter(|| {
            let res = gen.and_gate(&h, x, y, delta, gid);
            black_box(res);
        });
    });

    c.bench_function("half_gate_eval_and", move |bench| {
        let mut prg = RandPrg::new();
        let h = Aes::new(&[0u8; 16]);
        let gen = HalfGateGenerator;
        let ev = HalfGateEvaluator;

        let mut delta = prg.random_block();
        delta.set_lsb();
        let x_0 = prg.random_block();
        let x = [x_0, x_0 ^ delta];
        let y_0 = prg.random_block();
        let y = [y_0, y_0 ^ delta];
        let gid: usize = 1;

        let (_, table) = gen.and_gate(&h, x, y, delta, gid);

        bench.iter(|| {
            let res = ev.and_gate(&h, x[0], y[0], table, gid);
            black_box(res);
        });
    });

    c.bench_function("half_gate_aes", move |bench| {
        let mut prg = RandPrg::new();
        let h = Aes::new(&[0u8; 16]);
        let circ = Circuit::parse("circuits/aes_128_reverse.txt").unwrap();
        let half_gate = HalfGateGenerator;
        bench.iter(|| {
            let gb = half_gate.garble(&h, &mut prg, &circ).unwrap();
            black_box(gb);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
