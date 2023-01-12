use criterion::{black_box, criterion_group, criterion_main, Criterion};

use clmul::Clmul;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha12Rng::from_entropy();
    let a: [u8; 16] = rng.gen();
    let b: [u8; 16] = rng.gen();
    let mut a = Clmul::new(&a);
    let mut b = Clmul::new(&b);

    c.bench_function("clmul", move |bench| {
        bench.iter(|| {
            black_box(a.clmul(b));
        });
    });

    c.bench_function("clmul_reuse", move |bench| {
        bench.iter(|| {
            black_box(a.clmul_reuse(&mut b));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
