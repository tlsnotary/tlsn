use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use share_conversion_core::fields::{gf2_128::Gf2_128, Field};

fn bench_gf2_128_inverse(c: &mut Criterion) {
    let mut rng = ChaCha12Rng::from_entropy();
    let a: Gf2_128 = rng.gen();

    c.bench_function("inverse", move |bench| {
        bench.iter(|| {
            black_box(a.inverse());
        });
    });
}

criterion_group!(benches, bench_gf2_128_inverse);
criterion_main!(benches);
