use criterion::{black_box, criterion_group, criterion_main, Criterion};

use halo2_poseidon::poseidon::primitives::Spec;
use poseidon_circomlib::CircomlibSpec;

fn criterion_benchmark(c: &mut Criterion) {
    // Benchmark the time to load the constants.
    c.bench_function("constants", |b| {
        b.iter(|| {
            black_box(CircomlibSpec::<17, 16>::constants());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
