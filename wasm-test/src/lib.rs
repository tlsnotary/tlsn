#![feature(portable_simd)]
#![feature(slice_as_chunks)]
#![feature(slice_split_at_unchecked)]
#![feature(test)]
extern crate test;
use std::simd::{LaneCount, Simd, SupportedLaneCount};
use thiserror::Error;

/// This function transposes a matrix, which is encoded as a slice of bytes. The transposition is
/// applied on the bit level, meaning that each matrix element is a single bit. The number of rows
/// has to be a power of 2. The whole transposition consists of byte-level transposition, followed
/// by a bit-level transposition.
///
/// We use the following algorithm:
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
pub fn transpose<const N: usize>(matrix: &mut [u8], rows: usize) -> Result<(), TransposeError>
where
    LaneCount<N>: SupportedLaneCount,
{
    // Check that number of rows is a power of 2
    if rows & (rows - 1) != 0 {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that slice is rectangular
    if matrix.len() & (rows - 1) != 0 {
        return Err(TransposeError::MalformedSlice);
    }

    // Check that row length is multiple of Simd lane
    if matrix.len() & (N - 1) != 0 {
        return Err(TransposeError::InvalidLaneCount);
    }

    // This leads to errors due to the implementation of interleave
    if N == 1 {
        return Err(TransposeError::LaneCountOne);
    }

    // Normal transposition of byte elements
    // Has to be invoked for ld(rows) rounds
    unsafe {
        transpose_bytes::<N>(matrix, rows.trailing_zeros());
    }
    Ok(())
}

/// This is the byte-level transpose
unsafe fn transpose_bytes<const N: usize>(matrix: &mut [u8], rounds: u32)
where
    LaneCount<N>: SupportedLaneCount,
{
    let half = matrix.len() >> 1;
    let mut matrix_copy = vec![0_u8; half];
    for _ in 0..rounds as usize {
        matrix_copy.copy_from_slice(&matrix[..half]);
        let mut lanes: Vec<Simd<u8, N>> = matrix_copy
            .as_chunks_unchecked_mut::<N>()
            .iter_mut()
            .chain(&mut matrix[half..].as_chunks_unchecked_mut::<N>().iter_mut())
            .map(|lane| Simd::from_array(*lane))
            .collect();
        let (chunk1, chunk2) = lanes.split_at_mut_unchecked(half / N);
        for (k, (v1, v2)) in chunk1.iter_mut().zip(chunk2).enumerate() {
            (*v1, *v2) = v1.interleave(*v2);
            matrix[2 * k * N..(2 * k + 1) * N].copy_from_slice(&v1.to_array());
            matrix[(2 * k + 1) * N..(k + 1) * 2 * N].copy_from_slice(&v2.to_array());
        }
    }
}

#[derive(Error, Debug)]
pub enum TransposeError {
    #[error("Number of rows is not a power of 2")]
    InvalidNumberOfRows,
    #[error("Provided slice is not of rectangular shape")]
    MalformedSlice,
    #[error("Number of elements per row must be multiple of lane count")]
    InvalidLaneCount,
    #[error(" A lane count of 1 is not supported.")]
    LaneCountOne,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::{Distribution, Standard};
    use rand::prelude::*;
    use test::Bencher;

    fn random_matrix<T>(elements: usize) -> Vec<T>
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        (0..elements).map(|_| rng.gen::<T>()).collect()
    }

    #[test]
    fn test_transpose_bytes() {
        let rounds = 6;
        let mut m: Vec<u8> = random_matrix::<u8>(2_usize.pow(rounds) * 2_usize.pow(rounds));
        let original = m.clone();
        unsafe {
            transpose_bytes::<32>(&mut m, rounds);
            transpose_bytes::<32>(&mut m, rounds);
        }
        assert_eq!(m, original);
    }

    #[bench]
    fn bench_transpose_bytes(b: &mut Bencher) {
        let rounds = 8;
        let mut m: Vec<u8> = random_matrix::<u8>(2_usize.pow(rounds) * 2_usize.pow(rounds));
        b.iter(|| unsafe { transpose_bytes::<32>(&mut m, rounds) })
    }
}
