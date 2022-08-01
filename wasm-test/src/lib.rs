#![feature(portable_simd)]
#![feature(slice_as_chunks)]
#![feature(slice_split_at_unchecked)]
#![feature(test)]
extern crate test;
use std::ops::ShlAssign;
use std::simd::{LaneCount, Simd, SimdElement, SupportedLaneCount};
use thiserror::Error;

/// This function transposes a matrix of generic elements.
///
/// This implementation requires that the number of rows is a power of 2.
pub fn transpose<const N: usize, T>(matrix: &mut [T], rows: usize) -> Result<(), TransposeError>
where
    LaneCount<N>: SupportedLaneCount,
    T: Default + SimdElement + Copy,
{
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that slice is rectangular
    if matrix.len() & (rows - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    // Check that row length is a multiple of Simd lane
    if matrix.len() & (N - 1) != 0 {
        return Err(TransposeError::InvalidLaneCount);
    }

    // N == 1 leads to errors due to implementation of interleave
    // in portable_simd
    if N == 1 {
        return Err(TransposeError::LaneCountOne);
    }

    // Call transpose for ld(rows) rounds
    unsafe {
        transpose_unchecked::<N, T>(matrix, rows.trailing_zeros());
    }
    Ok(())
}

/// Unsafe matrix transpose
///
/// This function is an implementation of the byte-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to ensure that
///   - number of rows is a power of 2
///   - slice is rectangular (matrix)
///   - row length is a multiple of N
///   - N != 1
///   - rounds == ld(rows)
unsafe fn transpose_unchecked<const N: usize, T>(matrix: &mut [T], rounds: u32)
where
    LaneCount<N>: SupportedLaneCount,
    T: Default + SimdElement + Copy,
{
    let half = matrix.len() >> 1;
    let mut matrix_copy_half = vec![T::default(); half];
    let mut matrix_pointer;
    let (mut s1, mut s2): (Simd<T, N>, Simd<T, N>);
    for _ in 0..rounds as usize {
        matrix_copy_half.copy_from_slice(&matrix[..half]);
        matrix_pointer = matrix.as_mut_ptr();
        for (v1, v2) in matrix_copy_half
            .as_chunks_unchecked::<N>()
            .iter()
            .zip(matrix[half..].as_chunks_unchecked::<N>().iter())
        {
            (s1, s2) = Simd::from_array(*v1).interleave(Simd::from_array(*v2));
            std::ptr::copy_nonoverlapping(s1.to_array().as_ptr(), matrix_pointer, N);
            matrix_pointer = matrix_pointer.add(N);
            std::ptr::copy_nonoverlapping(s2.to_array().as_ptr(), matrix_pointer, N);
            matrix_pointer = matrix_pointer.add(N);
        }
    }
}

unsafe fn transpose_bits(matrix: &mut [u8], row_length: u32) {
    #[cfg(target_arch = "wasm32")]
    wasm_transpose_bits(matrix, row_length)
}

#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
#[inline]
unsafe fn wasm_transpose_bits(matrix: &mut [u8], row_length: usize) {
    use std::arch::wasm32::{u8x16_bitmask, v128};
    let simd_one = Simd::<u8, 16>::splat(1);
    let mut v: v128;
    let mut high_bits: u16;
    let mut s: Simd<u8, 16>;
    for row in matrix.chunks_mut(row_length) {
        let mut shifted_row = Vec::with_capacity(row_length);
        for _ in 0..8 {
            for chunk in row.as_chunks_unchecked_mut::<16>().iter_mut() {
                s = Simd::from_array(*chunk);
                v = v128::from(s);
                high_bits = u8x16_bitmask(v128::from(v));
                shifted_row.push((high_bits >> 8) as u8);
                shifted_row.push((high_bits & 0xff) as u8);
                s.shl_assign(simd_one);
                *chunk = s.to_array();
            }
        }
        row.copy_from_slice(&shifted_row)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn movemask_x86_64(s: Simd<u8, 16>) {
    use std::arch::x86_64::_mm256_movemask_epi8;
    use std::simd::u8x32;
}

#[derive(Error, Debug)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of elements per row must be a multiple of lane count")]
    InvalidLaneCount,
    #[error("A lane count of 1 is not supported.")]
    LaneCountOne,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::{Distribution, Standard};
    use rand::prelude::*;
    use test::{black_box, Bencher};

    fn random_matrix<T>(elements: usize) -> Vec<T>
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        (0..elements).map(|_| rng.gen::<T>()).collect()
    }

    #[test]
    fn test_transpose_bytes() {
        let rounds = 8;
        let mut m: Vec<u8> = random_matrix::<u8>(2_usize.pow(rounds) * 2_usize.pow(rounds));
        let original = m.clone();
        unsafe {
            transpose_unchecked::<32, u8>(&mut m, rounds);
            transpose_unchecked::<32, u8>(&mut m, rounds);
        }
        assert_eq!(m, original);
    }

    #[bench]
    fn bench_transpose_bytes(b: &mut Bencher) {
        let rounds = 11;
        let mut m: Vec<u8> = random_matrix::<u8>(2_usize.pow(rounds) * 2_usize.pow(rounds));
        b.iter(|| unsafe { black_box(transpose_unchecked::<32, u8>(&mut m, rounds)) })
    }
}
