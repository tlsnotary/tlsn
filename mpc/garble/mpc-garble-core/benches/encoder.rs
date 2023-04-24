use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_circuits::circuits::AES128;
use mpc_garble_core::{ChaChaEncoder, Encoder};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoder");

    group.bench_function("encode_aes128".to_string(), |b| {
        let encoder = ChaChaEncoder::new([0u8; 32]);
        b.iter(|| {
            black_box(
                AES128
                    .inputs()
                    .iter()
                    .map(|value| encoder.encode_by_type(0, &value.value_type()))
                    .collect::<Vec<_>>(),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
