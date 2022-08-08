use criterion::{black_box, criterion_group, criterion_main, Criterion};
use matrix_transpose::{transpose_bits, transpose_unchecked};
use rand::distributions::{Distribution, Standard};
use rand::prelude::*;

fn random_vec<T>(elements: usize) -> Vec<T>
where
    Standard: Distribution<T>,
{
    let mut rng = thread_rng();
    (0..elements).map(|_| rng.gen::<T>()).collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 1024;
    let columns = rows;
    let mut matrix_1: Vec<u8> = random_vec(rows * columns);
    let mut matrix_2: Vec<u8> = random_vec(rows * columns);

    c.bench_function("transpose", move |bench| {
        bench.iter(|| unsafe {
            black_box(
                #[cfg(feature = "simd-transpose")]
                transpose_unchecked::<32, _>(&mut matrix_1, rows.trailing_zeros() as usize),
                #[cfg(not(feature = "simd-transpose"))]
                transpose_unchecked(&mut matrix_1, rows.trailing_zeros() as usize),
            )
        });
    });

    c.bench_function("transpose_bits", move |bench| {
        bench.iter(|| black_box(transpose_bits(&mut matrix_2, rows)));
    });
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
