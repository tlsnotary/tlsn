#![feature(portable_simd)]
#![feature(slice_as_chunks)]
#![feature(slice_split_at_unchecked)]
#![feature(test)]
extern crate test;
use std::ops::ShlAssign;
use std::simd::{LaneCount, Simd, SimdElement, SupportedLaneCount};
use thiserror::Error;

/// This function transposes a matrix on the bit-level.
///
/// This implementation requires that the number of rows is a power of 2 and
/// that the matrix has at least 32 columns
pub fn transpose_bits(matrix: &mut [u8], rows: usize) -> Result<(), TransposeError> {
    const LANE_SIZE: usize = 32;
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that slice is rectangular
    if matrix.len() & (rows - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    // Check that row length is a multiple of LANE_SIZE
    let columns = matrix.len() / rows;
    if columns & (LANE_SIZE - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfColumns);
    }

    // Perform transposition on bit-level consisting of:
    // 1. normal transposition of elements
    // 2. single-row bit-level tranposition
    unsafe {
        transpose_unchecked::<LANE_SIZE, u8>(matrix, rows.trailing_zeros() as usize);
        transpose_bits_unchecked(matrix, columns);
    }
    Ok(())
}

/// Unsafe matrix transpose
///
/// This function transposes a matrix of generic elements. This function is an implementation of
/// the byte-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to ensure that
///   - number of rows is a power of 2
///   - slice is rectangular (matrix)
///   - row length is a multiple of N
///   - N != 1 c.f. https://github.com/rust-lang/portable-simd/issues/298
///   - rounds == ld(rows)
pub unsafe fn transpose_unchecked<const N: usize, T>(matrix: &mut [T], rounds: usize)
where
    LaneCount<N>: SupportedLaneCount,
    T: Default + SimdElement + Copy,
{
    let half = matrix.len() >> 1;
    let mut matrix_copy_half = vec![T::default(); half];
    let mut matrix_pointer: *mut T;
    let (mut s1, mut s2): (Simd<T, N>, Simd<T, N>);
    for _ in 0..rounds {
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

/// Unsafe single-row bit-level transpose
///
/// This function is an implementation of the bit-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to make sure that columns is a multiple of 16
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
#[inline]
unsafe fn transpose_bits_unchecked(matrix: &mut [u8], columns: usize) {
    use std::arch::wasm32::{u8x16_bitmask, v128};

    let simd_one = Simd::<u8, 16>::splat(1);
    let mut high_bits;
    let mut s: Simd<u8, 16>;
    for row in matrix.chunks_mut(columns) {
        let mut shifted_row = Vec::with_capacity(columns);
        for _ in 0..8 {
            for chunk in row.as_chunks_unchecked_mut::<16>().iter_mut() {
                s = Simd::from_array(*chunk);
                high_bits = u8x16_bitmask(s.reverse().into());
                shifted_row.extend_from_slice(&high_bits.to_be_bytes());
                s.shl_assign(simd_one);
                *chunk = s.to_array();
            }
        }
        row.copy_from_slice(&shifted_row)
    }
}

/// Unsafe single-row bit-level transpose
///
/// This function is an implementation of the bit-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to make sure that columns is a multiple of 32
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn transpose_bits_unchecked(matrix: &mut [u8], columns: usize) {
    use std::arch::x86_64::_mm256_movemask_epi8;

    let simd_one = Simd::<u8, 32>::splat(1);
    let mut high_bits;
    let mut s: Simd<u8, 32>;
    for row in matrix.chunks_mut(columns) {
        let mut shifted_row = Vec::with_capacity(columns);
        for _ in 0..8 {
            for chunk in row.as_chunks_unchecked_mut::<32>().iter_mut() {
                s = Simd::from_array(*chunk);
                high_bits = _mm256_movemask_epi8(s.reverse().into());
                shifted_row.extend_from_slice(&high_bits.to_be_bytes());
                s.shl_assign(simd_one);
                *chunk = s.to_array();
            }
        }
        row.copy_from_slice(&shifted_row)
    }
}

#[derive(Error, Debug)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of columns must be a multiple of lane count")]
    InvalidNumberOfColumns,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::{Distribution, Standard};
    use rand::prelude::*;
    use test::{black_box, Bencher};

    fn random_vec<T>(elements: usize) -> Vec<T>
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        (0..elements).map(|_| rng.gen::<T>()).collect()
    }

    #[test]
    fn test_transpose_unchecked() {
        let rounds = 8_u32;
        let mut rows = 2_usize.pow(rounds);
        let mut columns = 64;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let original = matrix.clone();
        unsafe {
            transpose_unchecked::<32, u8>(&mut matrix, rounds as usize);
        }

        (rows, columns) = (columns, rows);
        for (k, element) in matrix.iter().enumerate() {
            let row_number = k / columns;
            let column_number = k % columns;
            assert_eq!(*element, original[column_number * rows + row_number])
        }
    }

    #[test]
    fn test_transpose_bits_unchecked() {
        let columns = 2_usize.pow(8);
        let rows = 64;

        let mut matrix: Vec<u8> = random_vec::<u8>(columns * rows);
        let mut original = matrix.clone();
        unsafe {
            transpose_bits_unchecked(&mut matrix, columns);
        }

        for (row_index, row) in original.chunks_mut(columns).enumerate() {
            for k in 0..8 {
                for (l, chunk) in row.chunks(8).enumerate() {
                    let expected: u8 = chunk.iter().enumerate().fold(0, |acc, (m, element)| {
                        acc + (element >> 7) * 2_u8.pow(7_u32 - m as u32)
                    });
                    let actual = matrix[row_index * columns + columns / 8 * k + l];
                    assert_eq!(expected, actual);
                }
                let shifted_row = row.iter_mut().map(|el| *el << 1).collect::<Vec<u8>>();
                row.copy_from_slice(&shifted_row);
            }
        }
    }

    #[bench]
    fn bench_transpose_unchecked(b: &mut Bencher) {
        let rounds = 12_usize;
        let mut m: Vec<u8> =
            random_vec::<u8>(2_usize.pow(rounds as u32) * 2_usize.pow(rounds as u32));
        b.iter(|| unsafe { black_box(transpose_unchecked::<32, u8>(&mut m, rounds)) })
    }
}
