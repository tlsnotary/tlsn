use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::{BitOrder, WireGroup, AES_128};
use mpc_garble_core::{ChaChaEncoder, Encoder};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoder");

    let circ = AES_128.clone();
    group.bench_function(circ.id().clone().to_string(), |b| {
        let mut enc = ChaChaEncoder::new([0u8; 32], BitOrder::Msb0);
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
