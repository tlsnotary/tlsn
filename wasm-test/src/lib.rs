#![feature(portable_simd)]
#![feature(slice_as_chunks)]
#![feature(slice_split_at_unchecked)]
#![feature(test)]
extern crate test;
use std::simd::{LaneCount, Simd, SimdElement, SupportedLaneCount};
use thiserror::Error;

/// This function transposes a matrix of generic elements.
///
/// This implementation requires that the number of rows is a power of 2. This function is an
/// implementation of the byte-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
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

    // Normal transposition of byte elements
    // Has to be invoked for ld(rows) rounds
    unsafe {
        transpose_unchecked::<N, T>(matrix, rows.trailing_zeros());
    }
    Ok(())
}

/// Unsafe matrix transpose
///
/// Caller has to ensure that
///   - number of rows is a power of 2
///   - slice is rectangular (matrix)
///   - row length is a multiple of N
///   - N != 1
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
            .as_chunks_unchecked_mut::<N>()
            .iter_mut()
            .zip(&mut matrix[half..].as_chunks_unchecked_mut::<N>().iter_mut())
        {
            (s1, s2) = Simd::from_array(*v1).interleave(Simd::from_array(*v2));
            std::ptr::copy_nonoverlapping(s1.to_array().as_ptr(), matrix_pointer, N);
            matrix_pointer = matrix_pointer.add(N);
            std::ptr::copy_nonoverlapping(s2.to_array().as_ptr(), matrix_pointer, N);
            matrix_pointer = matrix_pointer.add(N);
        }
    }
}

#[derive(Error, Debug)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of elements per row must be a multiple of lane count")]
    InvalidLaneCount,
    #[error(" A lane count of 1 is not supported.")]
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
