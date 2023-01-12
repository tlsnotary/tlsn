use criterion::{criterion_group, criterion_main, Criterion};
use rand::{
    distributions::{Distribution, Standard},
    prelude::*,
};

fn random_vec<T>(elements: usize) -> Vec<T>
where
    Standard: Distribution<T>,
{
    let mut rng = thread_rng();
    (0..elements).map(|_| rng.gen::<T>()).collect()
}

#[inline]
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

#[inline]
fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

fn transpose_bits(m: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let bits: Vec<Vec<bool>> = m.iter().map(|row| u8vec_to_boolvec(row)).collect();
    let col_count = bits[0].len();
    let row_count = bits.len();

    let mut bits_: Vec<Vec<bool>> = vec![vec![false; row_count]; col_count];
    let mut m_: Vec<Vec<u8>> = Vec::with_capacity(col_count);

    for j in 0..row_count {
        for i in 0..col_count {
            bits_[i][j] = bits[j][i];
        }
    }

    for row in bits_.iter() {
        m_.push(boolvec_to_u8vec(row));
    }

    m_
}

fn transpose(m: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let col_count = m[0].len();
    let row_count = m.len();

    let mut m_: Vec<Vec<u8>> = vec![vec![0; row_count]; col_count];

    for j in 0..row_count {
        for i in 0..col_count {
            m_[i][j] = m[j][i];
        }
    }
    m_
}

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 1024;
    let columns = rows;
    let matrix = random_vec(rows * columns);

    let mut m1: Vec<u8> = matrix.clone();
    c.bench_function("transpose", move |bench| {
        bench.iter(|| unsafe {
            #[cfg(feature = "simd-transpose")]
            matrix_transpose::transpose_unchecked::<32, _>(&mut m1, rows.trailing_zeros() as usize);
            #[cfg(not(feature = "simd-transpose"))]
            matrix_transpose::transpose_unchecked(&mut m1, rows.trailing_zeros() as usize);
        });
    });

    let mut m2 = matrix.clone();
    c.bench_function("transpose_bits", move |bench| {
        bench.iter(|| matrix_transpose::transpose_bits(&mut m2, rows));
    });

    let m3: Vec<Vec<u8>> = matrix.clone().chunks(columns).map(|r| r.to_vec()).collect();
    c.bench_function("transpose_bits_baseline", move |bench| {
        bench.iter(|| transpose_bits(&m3));
    });

    let m4: Vec<Vec<u8>> = matrix.clone().chunks(columns).map(|r| r.to_vec()).collect();
    c.bench_function("transpose_baseline", move |bench| {
        bench.iter(|| transpose(&m4));
    });
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
