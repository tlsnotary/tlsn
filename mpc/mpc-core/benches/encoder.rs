use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::{Circuit, WireGroup, AES_128_REVERSE};
use mpc_core::garble::ChaChaEncoder;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoder");

    let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());
    group.bench_function(circ.id().clone().to_string(), |b| {
        let mut enc = ChaChaEncoder::new([0u8; 32], 0);
        b.iter(|| {
            black_box(
                circ.inputs()
                    .iter()
                    .map(|input| enc.encode(input.index() as u32, input))
                    .collect::<Vec<_>>(),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
