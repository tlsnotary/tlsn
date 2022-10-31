use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gf2_128::inverse;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha12Rng::from_entropy();
    let a: u128 = rng.gen();

    c.bench_function("inverse", move |bench| {
        bench.iter(|| {
            black_box(inverse(a));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
