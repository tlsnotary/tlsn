use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use share_conversion_core::gf2_128::inverse;

fn bench_gf2_128_inverse(c: &mut Criterion) {
    let mut rng = ChaCha12Rng::from_entropy();
    let a: u128 = rng.gen();

    c.bench_function("inverse", move |bench| {
        bench.iter(|| {
            black_box(inverse(a));
        });
    });
}

criterion_group!(benches, bench_gf2_128_inverse);
criterion_main!(benches);
